# What 

A [Wireshark](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html) packet dissector for the [LoRa packet forwarder protocol](https://github.com/Lora-net/packet_forwarder/blob/master/PROTOCOL.TXT).

This protocol is used by the [LoRa packet forwarder](https://github.com/Lora-net/packet_forwarder) to communicate between the Gateway and the remote LoRa server.

# Status 

Alpha. Has not seen heavy usage yet.

# Installation

## In short 

1. Remove `~/.config/wireshark`. Then:
2. `git clone https://github.com/danieroux/lora_pkt_fwd_wireshark_dissector.git ~/.config/wireshark`


## Slightly longer 

The [Wireshark configuration files section](https://www.wireshark.org/docs/wsug_html_chunked/ChAppFilesConfigurationSection.html) is relevant.

An example [init.lua](init.lua) is in this repo. It does some hacky work to get the [lora_pkt_fwd_proto](lora_pkt_fwd_proto) directory into the search path. You want your `init.lua` to do something like that. Or you want to put this plugin in the global configuration folder.

# Making .pcap files on a Multitech Conduit 

```sh
sudo tcpdump -s 65535 -i lo -n -w lora_pkt_fwd.pcap udp port 1700
```

You can then `scp` that file locally. The file can then be parsed, without the wireshark UI with:

```
tshark -r lora_pkt_fwd.pcap -V
```

On OSX, you can find `tshark` here if you installed the Wireshark app: `/Applications/Wireshark.app/Contents/MacOS/tshark`.

If that works, then the `.pcap` can be opened in the Wireshark GUI.

# Acknowledgements 

- [lora_pkt_fwd_proto/json.lua](lora_pkt_fwd_proto/json.lua) is from the [http://github.com/craigmj/json4lua](http://github.com/craigmj/json4lua) project.
