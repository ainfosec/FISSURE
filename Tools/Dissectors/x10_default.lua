custom_protocol = Proto("x10.default", "x10.default")

address_code = ProtoField.new("Address Code", "x10.default.address_code", ftypes.UINT8, nil, base.HEX, 0xff)
address_code_inverse = ProtoField.new("Address Code Inverse", "x10.default.address_code_inverse", ftypes.UINT8, nil, base.HEX, 0xff)
data_code = ProtoField.new("Data Code", "x10.default.data_code", ftypes.UINT8, nil, base.HEX, 0xff)
data_code_inverse = ProtoField.new("Data Code Inverse", "x10.default.data_code_inverse", ftypes.UINT8, nil, base.HEX, 0xff)

custom_protocol.fields = {address_code, address_code_inverse, data_code, data_code_inverse}

function custom_protocol.dissector(buffer, pinfo, tree)
  get_length = buffer:len()
  if get_length == 0 then return end

  pinfo.cols.protocol = custom_protocol.name

  local subtree = tree:add(custom_protocol, buffer(), "X10: Default")

  subtree:add_le(address_code, buffer(0,1))
  subtree:add_le(address_code_inverse, buffer(1,1))
  subtree:add_le(data_code, buffer(2,1))
  subtree:add_le(data_code_inverse, buffer(3,1))
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(50001, custom_protocol)
