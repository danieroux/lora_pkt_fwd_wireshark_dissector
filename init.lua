-- Get the path of this script in the hackiest possible way
-- https://stackoverflow.com/a/35072122
wot = debug.getinfo(1).source:match("@?(.*/)")
-- Add lora_pkt_fwd_proto dir in into package.path, relative to this script
package.path = wot .. "/lora_pkt_fwd_proto/?.lua;" .. package.path

-- Now we can require this from the current directory
require("lora_pkt_fwd_proto")
