print("loading rime dissector")

rime_proto = Proto("rime","Contiki Rime")
-- dissect
function rime_proto.dissector(buffer,pinfo,tree)
	pinfo.cols.protocol = "RIME"

	local mac_tree = tree:add(rime_proto, buffer(0, 9), "IEEE 802.15.4")
	local fcf_tree = mac_tree:add(rime_proto, buffer(0, 2), "Frame Control " .. tostring(buffer(0, 2)))
	fcf_tree:add(buffer(0,1), "Frame Type: ", buffer(0,1):bitfield(5,3))
	fcf_tree:add(buffer(0,1), "Security Enabled: ", buffer(0,1):bitfield(4,1))
	fcf_tree:add(buffer(0,1), "Frame Pending: ", buffer(0,1):bitfield(3,1))
	fcf_tree:add(buffer(0,1), "ACK Request: ", buffer(0,1):bitfield(2,1))
	fcf_tree:add(buffer(0,1), "PAN ID Compression: ", buffer(0,1):bitfield(1,1))

	fcf_tree:add(buffer(0,1), "Dest. Addr. Mode: ", buffer(1,1):bitfield(6,2))
	fcf_tree:add(buffer(0,1), "Frame Version: ", buffer(1,1):bitfield(4,2))
	fcf_tree:add(buffer(0,1), "Src. Addr. Mode: ", buffer(1,1):bitfield(2,2))

	mac_tree:add(buffer(2,1), "Sequence Number: " .. buffer(2,1):uint())
	mac_tree:add(buffer(3,2),"Source PAN: " .. tostring(buffer(4,1))..tostring(buffer(3,1)))
	mac_tree:add(buffer(5,2),"Destination Address: " .. tostring(buffer(6,1))..tostring(buffer(5,1)))
	mac_tree:add(buffer(7,2),"Source Address: " .. tostring(buffer(8,1))..tostring(buffer(7,1)))
	mac_tree:add(buffer(buffer:len()-2, 2), "CRC: ", buffer(buffer:len()-2, 2):uint())

	local rime_tree = tree:add(rime_proto, buffer(9, 4), "RIME")
	rime_tree:add(buffer(9,2), "Port: " .. buffer(9,2):le_uint())
	rime_tree:add(buffer(11,2),"Source Address: " .. buffer(11,1):uint() .. ":" .. buffer(12,1):uint())

	local data_tree = tree:add(rime_proto, buffer(13, buffer:len() - 15), "Payload")

	pinfo.cols.info = "    Rime " .. buffer(11,1):uint()..":"..buffer(7,1):uint().. " -> port " .. buffer(9,2):le_uint()
end

-- get wiretap table
table = DissectorTable.get("wtap_encap")
-- and add rime protocol
table:add(wtap["IEEE802_15_4"], rime_proto)


