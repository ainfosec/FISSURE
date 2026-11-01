custom_protocol = Proto("tpms.format1", "tpms.format1")

sensor_id = ProtoField.new("Sensor ID", "tpms.format1.sensor_id", ftypes.UINT32, nil, base.HEX, 0xfffffff0)
battery_status = ProtoField.new("Battery Status", "tpms.format1.battery_status", ftypes.UINT8, nil, base.HEX, 0x08)
counter = ProtoField.new("Counter", "tpms.format1.counter", ftypes.UINT8, nil, base.HEX, 0x06)
unknown1 = ProtoField.new("Unknown1", "tpms.format1.unknown1", ftypes.UINT8, nil, base.HEX, 0x01)
unknown2 = ProtoField.new("Unknown2", "tpms.format1.unknown2", ftypes.UINT8, nil, base.HEX, 0x80)
self_test_failed = ProtoField.new("Self-Test Failed", "tpms.format1.self_test_failed", ftypes.UINT8, nil, base.HEX, 0x40)
tire_pressure = ProtoField.new("Tire Pressure", "tpms.format1.tire_pressure", ftypes.UINT16, nil, base.HEX, 0x3fc0)
tire_pressure_complement = ProtoField.new("Tire Pressure Complement", "tpms.format1.tire_pressure_complement", ftypes.UINT16, nil, base.HEX, 0x3fc0)
tire_temperature = ProtoField.new("Tire Temperature", "tpms.format1.tire_temperature", ftypes.UINT16, nil, base.HEX, 0x3fc0)
crc = ProtoField.new("CRC", "tpms.format1.crc", ftypes.UINT16, nil, base.HEX, 0x3fc0)

custom_protocol.fields = {sensor_id, battery_status, counter, unknown1, unknown2, self_test_failed, tire_pressure, tire_pressure_complement, tire_temperature, crc}

function custom_protocol.dissector(buffer, pinfo, tree)
  get_length = buffer:len()
  if get_length == 0 then return end

  pinfo.cols.protocol = custom_protocol.name

  local subtree = tree:add(custom_protocol, buffer(), "TPMS: Format1")

  subtree:add(sensor_id, buffer(0,4))
  subtree:add_le(battery_status, buffer(3,1))
  subtree:add_le(counter, buffer(3,1))
  subtree:add_le(unknown1, buffer(3,1))
  subtree:add_le(unknown2, buffer(4,1))
  subtree:add_le(self_test_failed, buffer(4,1))
  subtree:add(tire_pressure, buffer(4,2))
  subtree:add(tire_pressure_complement, buffer(5,2))
  subtree:add(tire_temperature, buffer(6,2))
  subtree:add(crc, buffer(7,2))
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(50002, custom_protocol)
