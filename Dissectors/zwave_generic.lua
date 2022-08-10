custom_protocol = Proto("zwave.generic", "zwave.generic")

home_id = ProtoField.new("Home ID", "zwave.generic.home_id", ftypes.UINT32, nil, base.HEX, 0xffffffff)
source_node_id = ProtoField.new("Source Node ID", "zwave.generic.source_node_id", ftypes.UINT8, nil, base.HEX, 0xff)
frame_control = ProtoField.new("Frame Control", "zwave.generic.frame_control", ftypes.UINT16, nil, base.HEX, 0xffff)
length = ProtoField.new("Length", "zwave.generic.length", ftypes.UINT8, nil, base.HEX, 0xff)
destination_node_id = ProtoField.new("Destination Node ID", "zwave.generic.destination_node_id", ftypes.UINT8, nil, base.HEX, 0xff)
command_class = ProtoField.new("Command Class", "zwave.generic.command_class", ftypes.UINT8, nil, base.HEX, 0xff)
command = ProtoField.new("Command", "zwave.generic.command", ftypes.BYTES, nil, base.NONE, nil)  -- Variable Length
crc = ProtoField.new("CRC", "zwave.generic.crc", ftypes.UINT16, nil, base.HEX, 0xffff)

custom_protocol.fields = {home_id, source_node_id, frame_control, length, destination_node_id, command_class, command, crc}

function custom_protocol.dissector(buffer, pinfo, tree)
  get_length = buffer:len()
  if get_length == 0 then return end
  
  -- Length Field
  len_field_value = buffer(7, 1):uint()
  command_length = len_field_value - 12

  pinfo.cols.protocol = custom_protocol.name

  local subtree = tree:add(custom_protocol, buffer(), "ZWAVE: Generic")

  subtree:add(home_id, buffer(0,4))
  subtree:add(source_node_id, buffer(4,1))
  subtree:add(frame_control, buffer(5,2))
  subtree:add(length, buffer(7,1))
  subtree:add(destination_node_id, buffer(8,1))
  subtree:add(command_class, buffer(9,1))
  subtree:add(command, buffer(10,command_length))
  subtree:add(crc, buffer(10+command_length,2))
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(50003, custom_protocol)
