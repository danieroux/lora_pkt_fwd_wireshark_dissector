-- A Wireshark protocol dissector for:
-- https://github.com/Lora-net/packet_forwarder/blob/master/PROTOCOL.TXT
--
-- Relevant Wireshark APIs:
-- https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem
-- https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoField

-- Get the path of this script in the hackiest possible way
-- https://stackoverflow.com/a/35072122
wot = debug.getinfo(1).source:match("@?(.*/)")
-- Add it to the package search path 
package.path = wot .. "/?.lua;" .. package.path

-- Now we can require this in the directory
--
-- https://github.com/craigmj/json4lua
json = require("json")

lora_pkt_fwd_proto = Proto("lora_pkt_fwd","lora_pkt_fwd")
fields = lora_pkt_fwd_proto.fields

fields.packet_type = ProtoField.string("lora_pkt_fwd.packet_type", "Packet Type")
fields.dev_eui = ProtoField.new("Gateway DevEUI", "lora_pkt_fwd.dev_eui", ftypes.BYTES)

-- What is ProtoField.framenum? Would want this for "linking frames"
-- fields.packet_token = ProtoField.framenum("lora_pkt_fwd.packet_type.push", "Push Token", base.NONE, frametype.REQUEST)
fields.packet_token = ProtoField.uint32("lora_pkt_fwd.packet.token", "Packet Token", base.DEC)

fields.json = ProtoField.string("lora_pkt_fwd.json", "Whole JSON string")

function addJSONNode(tree, k, v)
	local added = tree:add(k, v)
	-- Cannot directly point to the place in the byte buffer for this node
	-- So we cannot filter on it, so it is useless trying to give it an abbreviation
	added:set_generated(true)
end

function addPacketSubtree(buffer, tree, packet_type)
	local token_buffer = buffer(1,2)
	local subtree = tree:add(fields.packet_type, buffer:range(), packet_type)

	subtree:add(fields.packet_token, token_buffer)

	return subtree
end

function addGateway(buffer, subtree)
	local gateway_buffer = buffer(4,11-4)
	subtree:add(fields.dev_eui, gateway_buffer)
end

-- packet type is used by the gateway mainly to forward the RF packets 
-- received, and associated metadata, to the server.
function PUSH_DATA(buffer, tree)
	local json_buffer = buffer(12)

	local json_decoded = json.decode(json_buffer:string())
	local rx_packets = json_decoded["rxpk"]
	local rx_stats = json_decoded["stat"]

	local subtree_label = "PUSH_DATA"
	if (rx_stats ~= nil) and (rx_packets == nil) then
		subtree_label = "PUSH_STATS"
	end

	local subtree = addPacketSubtree(buffer, tree, subtree_label)

	addGateway(buffer, subtree)
	-- https://github.com/Lora-net/packet_forwarder/blob/d0226eae6e7b6bbaec6117d0d2372bf17819c438/PROTOCOL.TXT#L124
	local json_subtree = subtree:add(fields.json, json_buffer, json_buffer:string())

	if (rx_packets) then
		for _, rx_packet in ipairs(rx_packets) do
			local rx_packet_tree = json_subtree:add("RX_PACKET")
			table.sort(rx_packet)
			for k, v in pairs(rx_packet) do
				addJSONNode(rx_packet_tree, k, v)
			end
		end
	end

	if (rx_stats) then
		local rx_stats_tree = json_subtree:add("STATS")
		table.sort(rx_stats)
		for k, v in pairs(rx_stats) do 
			addJSONNode(rx_stats_tree, k, v)
		end
	end
end

-- packet type is used by the server to acknowledge immediately all the PUSH_DATA packets received.
function PUSH_ACK(buffer, tree)
	addPacketSubtree(buffer, tree, "PUSH_ACK")
end

-- packet type is used by the gateway to poll data from the server
function PULL_DATA(buffer, tree)
	local subtree = addPacketSubtree(buffer, tree, "PULL_DATA")
	addGateway(buffer, subtree)
end

-- packet type is used by the server to confirm that the network route is 
-- open and that the server can send PULL_RESP packets at any time.
function PULL_ACK(buffer, tree)
	addPacketSubtree(buffer, tree, "PULL_ACK")
end

-- packet type is used by the server to send RF packets and associated 
-- metadata that will have to be emitted by the gateway.
function PULL_RESP(buffer, tree)
	local subtree = addPacketSubtree(buffer, tree, "PULL_RESP")

	local json_buffer = buffer(4)
	local json_subtree = subtree:add(fields.json, json_buffer, json_buffer:string())
	local tx_packet_tree = json_subtree:add("TX_PACKET")

	local tx_packet = json.decode(json_buffer:string())["txpk"]

	table.sort(tx_packet)

	for k, v in pairs(tx_packet) do
		addJSONNode(tx_packet_tree, k, v)
	end
end

-- packet type is used by the gateway to send a feedback to the server
-- to inform if a downlink request has been accepted or rejected by the gateway.
function TX_ACK(buffer, tree)
	local subtree = addPacketSubtree(buffer, tree, "TX_ACK")
	addGateway(buffer, subtree)

	-- If no JSON is present (empty string), this means than no error occured.
	-- (I don't know how to check for empty, this may very well error)
	local json_buffer = buffer(12)

	local json_subtree = subtree:add(fields.json, json_buffer, json_buffer:string())
	local tx_packet_ack_tree = json_subtree:add("TX_PACKET_ACK")

	local tx_packet_ack = json.decode(json_buffer:string())["txpk_ack"]

	table.sort(tx_packet_ack)

	for k, v in pairs(tx_packet_ack) do
		addJSONNode(tx_packet_ack_tree, k, v)
	end
end

lora_pkt_fwd_proto_table =
{
	[0] = PUSH_DATA,
	[1] = PUSH_ACK,
	[2] = PULL_DATA,
	-- This is the order in the PROTOCOL.txt
	[4] = PULL_ACK,
	[3] = PULL_RESP,
	[5] = TX_ACK,
}

function lora_pkt_fwd_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "lora_pkt_fwd"

    local subtree = tree:add(lora_pkt_fwd_proto, buffer(), "lora_pkt_fwd")
    local packet_type = buffer(3, 1):uint()

    local packet_func = lora_pkt_fwd_proto_table[packet_type];

    if (packet_func) then
	    packet_func(buffer, subtree)
    else
	    subtree:add(buffer, "Unknown lora_pkt_fwd packet. How? " .. packet_type)
    end
end

-- load the udp.port table
udp_table = DissectorTable.get("udp.port")

-- register on port 1700, the standard port on Multitech
udp_table:add(1700, lora_pkt_fwd_proto)
