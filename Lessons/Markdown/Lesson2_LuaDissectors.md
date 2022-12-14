---
Wireshark dissectors are protocol parsers that are responsible for the filters and information displayed to the user. There are seemingly hundreds of dissectors built into Wireshark, but there will always be a case for adding custom dissectors for new protocols. Wireshark is written in C and dissectors for Wireshark are generally also written in C. Fortunately, Wireshark has a Lua implementation that does not require compiling or editing multiple support files.

This lesson will outline the procedure for creating a Lua Wireshark Dissector. FISSURE can assist in creating a basic Lua dissector to help those with no prior Lua experience. More advanced dissector rules can always be added manually once an understanding is achieved.

## Table of Contents
1. [References](#references)
2. [FISSURE Sniffing](#fissure_sniffing)
3. [Creating with FISSURE](#creating)
4. [Lua Dissector Examples](#example)


<div id="references"/> 

## Reference Material
Lua is a lightweight, high-level, multi-paradigm programming language. I encourage you to look at the Lua crash course in the first link to get a feel for the language if you have never worked with it. It is a useful language to know because embedded devices may have a Lua library that could allow an attacker to run commands native to the device.
- https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html
- https://wiki.wireshark.org/Lua/Examples
- https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html

<div id="fissure_sniffing"/> 

## FISSURE Sniffing
FISSURE is designed to run demodulation flow graphs as a part of its Protocol Discovery component with the goal of recursively identifying a protocol and ultimately producing a bitstream for a suspected protocol. The bits produced from the demodulation flow graphs can either go to a circular buffer for further analysis (unknown protocol) or straight to Wireshark through something like a UDP sink (known protocol). 

The "Sniffer" buttons in the _PD>>Sniffer_ tab are designed to run flow graphs that pipe the demodulation flow graph bits (or bits from another source) into Wireshark via a UDP port registered to an existing Lua dissector. All data going into Wireshark over that UDP port will be parsed by the Lua dissector. A unique UDP port/dissector can be assigned to a single protocol or to the different packet types that make up the protocol. 

The bits from the demodulation flow graphs are streamed by GNU Radio in one of three ways:
  1. Stream
  2. Tagged Stream
  3. Message/PDU

There will likely only be one "Sniffer" button/Sniffer flow graph that corresponds to the GNU Radio streaming method used in any given demodulation flow graph.

<div id="creating"/> 

## Creating with FISSURE
The _PD>>Dissectors_ tab is used to view and create Lua dissectors for protocols in the FISSURE library. Dissectors already assigned to a packet type will show up in the "Existing Dissector" combobox. Clicking the "Edit" button will allow the user to edit files in the `/FISSURE/Dissectors` folder. Any changes will require the "Update All Dissectors" button to be clicked. This button copies all dissector files to the `~/.config/Wireshark/Plugins/Dissectors` folder which is one of the default locations Wireshark uses for Lua scripts. Dissectors placed in this folder should show up automatically in the _Help>>About Wireshark>>Plugins_ tab.

To create a new Lua dissector, click the "New" button and the tab will be populated with FISSURE library information for the selected packet type. The items the user can change are:
- *Filter Name*: This is what gets typed in the Wireshark display filter to filter the data
- *Tree Name*: This is the name of the tree/dropdown in the Wireshark packet details frame
- *UDP Port*: This is the unique UDP port the bits must enter to be parsed by the dissector
- *Display Name*: The name for the field in the Wireshark packet details frame
- *Filter Name*: The filter name for the field that can be entered into the Wireshark display filter
- *Type*: A format for the ProtoField that dictates how the bits are interpreted
- *Base*: A format for the ProtoField that determines how field values are displayed
- *Bitmask*: Used to assign bit-level field values 
- *Buffer Location*: The index and length used when adding values to the subtree

The "Preview" button will show the Lua dissector that will be auto-generated by FISSURE. The "Save As" button is used to save the file and update the FISSURE library with the dissector name and port.

<div id="example"/> 

## Lua Dissector Examples

### Example 1

```
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
```

### Example 2

```
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
```

### Example 3

```
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
```
