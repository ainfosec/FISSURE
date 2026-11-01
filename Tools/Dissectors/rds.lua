-- lua wireshark dissector for RDS (Radio Data System)
-- put this file in: ~/.config/wireshark/plugins/rds.lua
-- or in (old location): ~/.wireshark/plugins/rds.lua
-- This dissector must be placed after checkword is processed

-- TODO
-- Add version B to decoding (May not be useful though, as B is just a lesser version of A)
-- Convert all groups to table format
-- Further decode groups:
--      Group 3: all known AID applications
--      Group 5: figure out transparent data segment
--      Group 7: Paging
--      Group 8/9: TMC/EAS
--      Group 13: Enhanced radio paging spec  # may not be worth it
--      Group 14: Decode info block
--      Group 15: Decode Program service name segment

-- Current supported groups (only bit mapping) todo not updated
-- Baseband, Group 0, 1, 2, 3, 4, 5, 7, 10, 13, 14, 15
-- Current enhanced support (decoding done)
-- Group 0, 2

-- lists
local _PROGRAM_TYPE_CODES = {
    "None",
    "News",
    "Information",
    "Sports",
    "Talk",
    "Rock",
    "Classic Rock",
    "Adult Hits",
    "Soft Rock",
    "Top 40",
    "Country",
    "Oldies",
    "Soft",
    "Nostalgia",
    "Jazz",
    "Classical",
    "Rhythm and Blues",
    "Soft Rhythm and Blues",
    "Foreign Language",
    "Religious Music",
    "Religious Talk",
    "Personality",
    "Public",
    "College",
    "Unassigned",
    "Unassigned",
    "Unassigned",
    "Unassigned",
    "Unassigned",
    "Weather",
    "Emergency Test",
    "Emergency | ALERT! | ALERT!_ALERT!",
}
rds_proto = Proto("rds","Radio Data System (RDS)")  -- Proto.new(name, desc)
-- Baseband
local baseband = {
pi = ProtoField.uint16("rds.pi", "PI code", base.HEX, nil, nil, "Program Identification (PI) code"),
group_type = ProtoField.uint16("rds.group", "Group type code", base.DEC, nil, 0xf000, "Group type code (0-15)"),
version_code = ProtoField.uint16("rds.version", "Version code", base.DEC, nil, 0x0800, "Version code (A=0, B=1)"),
tp = ProtoField.uint16("rds.tp", "Traffic Program Flag", base.BOOLEAN, nil, 0x0400, "Traffic Program Identification Flag (0=no broadcast, 1=broadcast)"),
pty = ProtoField.uint16("rds.pty", "Program type code", base.DEC, nil, 0x03e0, "Program type code (0-31)"),
}
-- Group 0
local group00 = {
ta = ProtoField.uint16("rds.g0_ta", "Traffic Announcement", base.BOOL, nil, 0x0010, "Used with the tp code to give info on traffic broadcasting, see 3.2.1.3"),
ms = ProtoField.uint16("rds.g0_ms", "Music-speech switch code", base.BOOL, nil, 0x0008, "0 indicates speech or 1 indicates music is currently being broadcast"),
di = ProtoField.uint16("rds.g0_di", "Decoder-indentification control code", base.BOOL, nil, 0x0004, ""),
address = ProtoField.uint16("rds.g0_address", "Prog service name and DI segment address", base.DEC, nil, 0x0003, "Deviation from core spec; This is the address of both the name segment and the DI code, and thus was given its own field"),
af1 = ProtoField.uint8("rds.g0_af1", "AF1 code", base.DEC, nil, nil, "First Alternate Frequency (AF) code"),
af2 = ProtoField.uint8("rds.g0_af2", "AF2 code", base.DEC, nil, nil, "Second Alternate Frequency (AF) code"),
name = ProtoField.string("rds.g0_name", "Program service name segment", base.ASCII, nil, nil, ""),
}
local f_g0_altfreq = ProtoField.float("rds.g0_altfreq", "Alternate Frequency", "Alternate Frequency for this station")  -- used for calc
-- Group 1
local group01 = {
pg_codes = ProtoField.uint16("rds.g1_pg_codes", "Radio Paging Codes", base.DEC, nil, 0x001f, "Radio Paging Codes, see annex M"),
label_codes = ProtoField.uint16("rds.label_codes", "Slow Labelling Codes", base.HEX, nil, nil, "Slow labelling codes, see 3.1.5.2 notes"),
item_num = ProtoField.uint16("rds.item_num", "Program item number code", base.HEX, nil, nil, "Program item number code; Day, hour, minute"),
}
-- Group 2
local f_g2_text_flag = ProtoField.uint16("rds.g2_text_flag", "Text A/B flag", base.BOOLEAN, nil, 0x0010, "Text clear/reset flag")
local f_g2_address = ProtoField.uint16("rds.g2_address", "Text Address", base.DEC, nil, 0x000f, "Text segment address code (DEC*4 + 1)")
local f_g2_radio_text = ProtoField.string("rds.g2_rt", "Radio Text", base.ASCII, nil, nil, "Radio text segment")
-- Group 3
local f_g3_app_gtc = ProtoField.uint16("rds.g3_app_gtc", "Application Group Type Code", base.DEC, nil, 0x001e, "Application Group Type Code; See 3.1.5.4")
local f_g3_version = ProtoField.uint16("rds.g3_version", "Application Group Type Code Version", base.BOOL, nil, 0x0001, "Version to app_gtc field")
local f_g3_msg = ProtoField.uint16("rds.g3_msg", "Message bits", base.HEX, nil, nil, "Message bits; See 3.1.5.4")
local f_g3_aid = ProtoField.uint16("rds.g3_aid", "Application Identification", base.HEX, nil, nil, "Application Identification; See 3.1.5.4")
-- Group 4
local f_g4_spare = ProtoField.uint16("rds.g4_spare", "Spare bits", base.DEC, nil, 0x001c, "Spare bits")
local f_g4_julian = ProtoField.uint32("rds.g4_julian", "Modified Julian Day code", base.HEX, nil, 0x0003fffe, "Modified Julian Day code; see annex G")
local f_g4_hour = ProtoField.uint16("rds.g4_hour", "Hour", base.DEC, nil, 0x01f0, "Hour; coded as binary number 0-23") -- inbetween checkword
local f_g4_minute = ProtoField.uint16("rds.g4_minute", "Minute", base.DEC, nil, 0x0fc0, "Minute; coded as binary 0-59, rest isn't used")
local f_g4_local_flag = ProtoField.uint16("rds.g4_local_flag", "Local time offset flag", base.BOOLEAN, nil, 0x0020, "sense of offset, 0= +, 1= -")
local f_g4_local_offset = ProtoField.uint16("rds.g4_local_offset", "Local time offset", base.DEC, nil, 0x001f, "Local time offset; expressed in multiples of half hours")
-- Group 5
local f_g5_address = ProtoField.uint16("rds.g5_address", "Address", base.DEC, nil, 0x001f,"Address code identifies \"channel number\" (out of 32) to which the data are addressed")
local f_g5_data = ProtoField.uint32("rds.g5_data", "Transparent data segment", base.HEX, nil, nil, "Sends data like radio text, but messages of any length/format allowed")
-- Group 6 (in-house or ODA) (using generic)
-- Group 7  annex M
local f_g7_paging_ab = ProtoField.uint16("rds.g7_paging_ab", "Paging A/B", base.BOOL, nil, 0x0010, "Notifies new or repeated call when value is changed")
local f_g7_address = ProtoField.uint16("rds.g7_address", "Paging segment address code", base.DEC, nil, 0x000f, "Indicates message contents based on annex M table")
local f_g7_paging = ProtoField.uint32("rds.g7_paging", "Paging", base.HEX, nil, nil, "Message/data")
-- Group 8 Traffic Message Channel or ODA; need CEN standard ENV 12313-1
-- Being based off of power point from blackhat/defcon rather than spec paper
local f_g8_t = ProtoField.uint16("rds.g8_t", "T multi group message", base.BOOL, nil, 0x0010, "Flag used in multi group messages")
local f_g8_f = ProtoField.uint16("rds.g8_f", "F multi group message", base.BOOL, nil, 0x0008, "Flag used in multi group messages")
local f_g8_dp = ProtoField.uint16("rds.g8_dp", "Duration and Persistance", base.DEC, nil, 0x0007, "Duration and Persistance")
local f_g8_d = ProtoField.uint16("rds.g8_d", "D multi group message", base.BOOL, nil, 0x8000, "Flag used in multi group messages")
local f_g8_pn = ProtoField.uint16("rds.g8_pn", "+/- direction", base.BOOL, nil, 0x4000, "+/- Direction")
local f_g8_extent = ProtoField.uint16("rds.g8_extent", "Event Extension", base.DEC, nil, 0x3800, "Event Extension")
local f_g8_event = ProtoField.uint16("rds.g8_event", "Event Code", base.HEX, nil, 0x07ff, "Event Code (see also TMDD - Traffic Management Data Directory)")
local f_g8_location = ProtoField.uint16("rds.g8_location", "Location code", base.HEX, nil, nil, "Location Code (DAT Location Table - TMCF-LT-EF-MFF-v06)")
-- Group 9 Emergancy Warning systems or ODA
-- Please forgive me for this massive list, it hurt
local group09 = {
address = ProtoField.uint16("rds.g9_address", "Address Code", base.DEC, nil, 0x001f, "Address code, used for corresponding block lookup"),
    -- address code = 0
spares1 = ProtoField.uint8("rds.g9_spares1", "Spares", base.DEC, nil, 0xf0, "Spares"),
org = ProtoField.uint8("rds.g9_org", "Originator", base.DEC, nil, 0x0f, "Originator, use table 2"),
eventchar = ProtoField.string("rds.g9_eventchar", "Event Character", base.ASCII, nil, nil, "Event Character"),
    -- address code = 1
pssccc = ProtoField.uint16("rds.g9_pssccc", "PSSCCC Count", base.DEC, nil, 0xfe00, "The PSSCCC Count represents the total number of PSSCCC codes that comprise the warning message"),
portion = ProtoField.uint16("rds.g9_portion", "Portion Code", base.DEC, nil, 0x01fe, "Portion Code"),
state_fips = ProtoField.uint16("rds.g9_state_fips", "State FIPS Number", base.DEC, nil, 0x01fc, "State FIPS Number"),  -- number corresponding to code, such as NY=36. No idea why it needs 2^7
country_fips = ProtoField.uint16("rds.g9_country_fips", "Country FIPS Number", base.DEC, nil, 0x01ff, "Country FIPS Number"),  -- Country code number
    -- address code = 2
hours = ProtoField.uint16("rds.g9_hours", "Hours", base.DEC, nil, 0xfe00, "Event Duration - Hours"),
minutes = ProtoField.uint16("rds.g9_minutes", "Minutes", base.DEC, nil, 0x0180, "Event Duration - Minutes"),
juliandate = ProtoField.uint16("rds.g9_juliandate", "Julian Date", base.NULL, nil, 0x7fc0, "Message Origination - Julian Date"),
hours_org = ProtoField.uint16("rds.g9_hours_org", "Hours", base.DEC, nil, 0x3e00, "Message Origination - Hours"),
minutes_org = ProtoField.uint16("rds.g9_minutes_org", "Minutes", base.DEC, nil, 0x01f8, "Message Origination - Minutes"),
spares2 = ProtoField.uint16("rds.g9_spares2", "Spares", base.DEC, nil, 0x0007, "Spares"),
    -- address code = 3
id_start = ProtoField.string("rds.g9_id_start", "ID Character 1-4", base.ASCII, nil, nil, "ID Character 1(left-most)-4"),
    -- address code = 4
id_end = ProtoField.string("rds.g9_id_end", "ID Character 5-8", base.ASCII, nil, nil, "ID Character 5-8"),
    -- 5 <= address code <=29 These may be used freely by service provider
data = ProtoField.uint16("rds.g9_data", "Data", base.HEX, nil, nil, "Data; Used freely by service provider"),
    -- address = 30/31
alt_freq = ProtoField.uint8("rds.g9_alt_freq1", "Alternative Frequency", base.DEC, nil, nil, "Alternative Frequency (ON)"),
pi_eas = ProtoField.uint16("rds.g9_pi_eas", "PI EAS (ON)", base.HEX, nil, nil, "PI EAS (ON)"),
}
-- Group 10
local f_g10_flag = ProtoField.uint16("rds.g10_flag", "Flag", base.BOOL, nil, 0x0010, "Toggled when change is being made")
local f_g10_spare = ProtoField.uint16("rds.g10_spare", "Spare bits", base.DEC, nil, 0x000e, "Spare")
local f_g10_address = ProtoField.uint16("rds.g10_address", "PTYN Segment Address", base.DEC, nil, 0x0001, "Address of name, 0 = [1-4] 1 = [5-8]")
local f_g10_name = ProtoField.string("rds.g10_name", "Program Type Name segment", base.ASCII, nil, nil, "Additional Program Type name")
-- Group 11 ODA (using generic)
-- Group 12 ODA (using generic)
-- Group 13
local f_g13_info1 = ProtoField.uint16("rds.g10_info1", "Information Field", base.HEX, nil, 0x0018, "info field; section M.3")
local f_g13_sty = ProtoField.uint16("rds.g10_sty", "STY", base.DEC, nil, 0x0007, "Lookup codes at section 3.1.5.17")
local f_g13_info2 = ProtoField.uint16("rds.g10_info2", "Information Field", base.HEX, nil, nil, "info field; section M.3")
local f_g13_info3 = ProtoField.uint16("rds.g10_info3", "Information Field", base.HEX, nil, nil, "info field; section M.3")
-- Group 14
local f_g14_tp = ProtoField.uint16("rds.g15_tp", "Traffic Program (ON)", base.BOOL, nil, 0x0010, "TRaffic Program flag of other network")
local f_g14_variant = ProtoField.uint16("rds.g15_variant", "Variant code", base.DEC, nil, 0x000f, "See seciotn 3.1.5.19 for code table")
local f_g14_info = ProtoField.uint16("rds.g15_info", "Information block", base.HEX, nil, nil, "Info depends on variant code")
local f_g14_pi = ProtoField.uint16("rds.g15_pi", "PI (ON)", base.HEX, nil, nil, "PI of other network")
-- Group 15
local f_g15_ta = ProtoField.uint16("rds.g15_ta", "Traffic Announcement", base.BOOLEAN, nil, 0x0010, "Traffic Announcement code")
local f_g15_spare = ProtoField.uint16("rds.g15_spare", "Spare bits", base.HEX, nil, 0x000e, "Spare bits")
local f_g15_seg_addr = ProtoField.uint16("rds.g15_seg_addr", "PS Segment Address", base.BOOLEAN, nil, 0x0001, "Program Service address")
local f_g15_name = ProtoField.string("rds.g15_name", "Program service name segment", base.ASCII, nil, nil, "Program service name segment; See annex E")
-- Undefined/generic; These are to be used for Open Data Applications, or In-House applications
local f_x_blk2 = ProtoField.uint16("rds.blk2_unkown", "Block 2 unkown/generic", base.HEX, nil, 0x001f, "Block 2 unkown or generic. Use of ODA or In-house")
local f_x_blk3 = ProtoField.uint16("rds.blk3_unkown", "Block 3 unkown/generic", base.HEX, nil, nil, "Block 3 unkown or generic. Use of ODA or In-house")
local f_x_blk4 = ProtoField.uint16("rds.blk4_unkown", "Block 4 unkown/generic", base.HEX, nil, nil, "Block 4 unkown or generic. Use of ODA or In-house")
-- ODA fields
local radiotestplus = {
rfu = ProtoField.uint16("rds.rtp_rfu", "RT+ Reserved", base.DEC, nil, 0xe000, "Reservered for future use, set 0"),
cbflag = ProtoField.uint16("rds.rtp_cbflag", "RT+ CB Flag", base.DEC, nil, 0x1000, "Specifies if there's a template in use"),
scb = ProtoField.uint16("rds.rtp_scb", "RT+ Server control bits", base.DEC, nil, 0x0f00, "Used to differentiate stations if two stations have the same PI code"),
template_number = ProtoField.uint16("rds.rtp_template_number", "RT+ Template number", base.DEC, nil, 0x00ff, "Number that specifies the template")
}


rds_proto.fields = {
    baseband["pi"], baseband["group_type"], baseband["version_code"], baseband["tp"], baseband["pty"],
    group00["ta"], group00["ms"], group00["di"], group00["address"], group00["af1"], group00["af2"], group00["name"], f_g0_altfreq,
    group01["pg_codes"], group01["label_codes"], group01["item_num"],
    f_g2_text_flag, f_g2_address, f_g2_radio_text,
    f_g3_app_gtc, f_g3_version, f_g3_msg, f_g3_aid,
    f_g4_spare, f_g4_julian, f_g4_hour, f_g4_minute, f_g4_local_flag, f_g4_local_offset,
    f_g5_address, f_g5_data,

    f_g7_paging_ab, f_g7_address, f_g7_paging,
    f_g8_t, f_g8_f, f_g8_dp, f_g8_d, f_g8_pn, f_g8_extent, f_g8_event, f_g8_location,
    group09["address"], group09["spares1"], group09["org"], group09["eventchar"], group09["pssccc"], group09["portion"],
    group09["state_fips"], group09["country_fips"], group09["hours"], group09["juliandate"], group09["hours_org"],
    group09["minutes_org"], group09["spares2"], group09["id_start"], group09["id_end"], group09["data"],
    group09["alt_freq"], group09["pi_eas"],
    f_g10_flag, f_g10_spare, f_g10_address, f_g10_name,

    f_g13_info1, f_g13_sty, f_g13_info2, f_g13_info3,
    f_g14_tp, f_g14_variant, f_g14_info, f_g14_pi,
    f_g15_ta, f_g15_spare, f_g15_seg_addr, f_g15_name,
    f_x_blk2, f_x_blk3, f_x_blk4,
    radiotestplus["rfu"], radiotestplus["cbflag"], radiotestplus["scb"], radiotestplus["template_number"]
}

-- -------------------------------------------------- Decoding ---------------------------------------------------------
function rds_proto.dissector(tvb,pinfo,tree)
    pinfo.cols.protocol:set("RDS")
    pinfo.cols.info:set("")
    local t = tree:add(rds_proto,tvb:range(0,8))  -- 8 bytes after RFtap preamble, No idea what the ABCD is for

    -- Program Identification (PI), aka station ID
    local pi_code = tvb:range(0,2):uint()            -- fetch value
    t:add(baseband["pi"], tvb:range(0,2))                      -- put in tree
    -- RDS frame type and version
    local group_type = tvb:range(2,2):bitfield(0,4)  -- fetch value
    t:add(baseband["group_type"], tvb:range(2,2))              -- put in tree
    local version_code = tvb:range(2,2):bitfield(4,1)  -- etc...
    t:add(baseband["version_code"], tvb:range(2,2))
    t:add(baseband["tp"], tvb:range(2,2))
    t:add(baseband["pty"], tvb:range(2,2))
    local f_pty_name = ProtoField.string("rds.pty_name", "PTY code to name", base.ASCII, nil, 0x03e0)
    t:add(f_pty_name, tvb:range(2,2), "PTY: " .. _PROGRAM_TYPE_CODES[tvb:range(2,2):bitfield(6, 5) + 1])

    local function decode_PI(pi_code)  -- for US standard todo; add special PI codes
        local station_name = ""
        local qou = 0
        local math = require "math"
        if pi_code < 4096 then
            return "EROR"
        elseif pi_code >= 4096 and pi_code <= 21671 then
            pi_code = pi_code - 4096
            station_name = station_name .. 'K'

        elseif pi_code >= 21672 and pi_code <= 39247 then
            pi_code = pi_code - 21672
            station_name = station_name .. 'W'
        elseif pi_code > 39247 and pi_code < 45056 then
            return "EROR"
        elseif pi_code >= 45056 then
            return "EURO"
        end
        qou = math.floor(pi_code/676)
        pi_code = pi_code%676
        station_name = station_name .. string.char(qou + 65)
        qou = math.floor(pi_code/26)
        pi_code = pi_code%26
        station_name = station_name .. string.char(qou + 65)
        station_name = station_name .. string.char(pi_code + 65)

        return station_name
    end

    -- Wireshark INFO column
    pinfo.cols.src:set(decode_PI(pi_code) .. string.format(' GRP=%u%s', group_type, (version_code==0 and 'A' or 'B')))

    -- Add station name to INFO column
    if group_type == 0 then
        local name_fragment = tvb(6,2):string()
        pinfo.cols.info:append(' <' .. name_fragment .. '>')  -- Program Service name segment
    end

    -- helper function for decoding Alternate Frequency code
    local function decode_altfreq(offset)
        local af = tvb:range(offset,1):uint()
        if af > 0 and af <= 204 then
            local s
            local freq_Hz = 87.6e6 + 0.1e6*(af-1)  -- field value (Hz)
            local freq_MHz = freq_Hz/1e6+0.01  -- for display (MHz)
            -- add Alternate Frequency field to dissection tree
            s = string.format('Alternate Frequency: %.1f MHz', freq_MHz)
            t:add(f_g0_altfreq, tvb:range(offset,1), freq_Hz, s)
            -- Add Alternate Frequency to INFO column
            pinfo.cols.info:append(string.format(' AF=%.1fMHz', freq_MHz))
        end
    end
    -- Decode Group 0 Alternate Frequency fields
    if group_type == 0 and version_code == 0 then
        t:add(group00["ta"], tvb:range(2,2))
        t:add(group00["ms"], tvb:range(2,2))
        t:add(group00["di"], tvb:range(2,2))
        t:add(group00["address"], tvb:range(2,2))
        t:add(group00["af1"], tvb:range(4,1))  -- rds.af1 (raw code)
        decode_altfreq(4)             -- rds.altfreq (frequency in Hertz)
        t:add(group00["af2"], tvb:range(5,1))  -- rds.af2 (raw code)
        decode_altfreq(5)             -- rds.altfreq (frequency in Hertz)
        t:add(group00["name"], tvb:range(6,2))
    -- Decode Group 1 Program Item Number and slow labeling codes
    elseif group_type == 1 and version_code == 0 then
        t:add(group01["pg_codes"], tvb:range(2,2))
        t:add(group01["label_codes"], tvb:range(4, 2))
        t:add(group01["item_num"], tvb:range(6, 2))
    -- Decode Group 2 Radio Text Segment fields
    elseif group_type == 2 and version_code == 0 then
        -- Text flag
	    t:add(f_g2_text_flag, tvb:range(2,2))
        -- segment address
        local address = tvb:range(2,2):bitfield(12, 4)
        t:add(f_g2_address, tvb:range(2,2))
        -- text
	    local rad_text = tvb:range(4, 4)
        t:add(f_g2_radio_text, rad_text)
	    pinfo.cols.info:append(' Text=' .. rad_text:string())
        pinfo.cols.info:append(' Start=' .. (address*4))
        pinfo.cols.info:append(' Flag=' .. tvb:range(2,2):bitfield(11,1))
    -- Decode Group 3 Application identification for Open data
    elseif group_type == 3 and version_code == 0 then
        local agtc = tvb:range(2,2):bitfield(11, 4)  -- Application Group Type Code
        local version = tvb:range(2,2):bitfield(15,1)  -- ^ version
        local aid = tvb:range(6,2):uint()  -- Application Identification
        t:add(f_g3_app_gtc, tvb:range(2,2))
        t:add(f_g3_version, tvb:range(2,2))
        t:add(f_g3_msg, tvb:range(4,2))
        t:add(f_g3_aid, tvb:range(6,2))
        pinfo.cols.info:append(' GRP=' .. agtc)
        if aid == 0x4BD7 then
            -- TODO message bits field still in window, replace it with these
            t:add(radiotestplus["rfu"], tvb:range(2,2))
            t:add(radiotestplus["cbflag"], tvb:range(2,2))
            t:add(radiotestplus["scb"], tvb:range(2,2))
            t:add(radiotestplus["template_number"], tvb:range(2,2))
            pinfo.cols.info:append(' AID=RadioText Plus')
        elseif aid == 0xC549 then
            pinfo.cols.info:append(' AID=Smart Grid Broadcast Channel')
        elseif aid == 0x0093 then
            pinfo.cols.info:append(' AID=Cross referencing DAB within RDS')
        elseif aid == 0xE911 then
            if agtc == 9 and version == 0 then
                pinfo.cols.info:append(' AID=EAS')
                -- something special related to EAS
            else
                pinfo.cols.info:append(' AID=Not Implemented')
            end
        else
            pinfo.cols.info:append(' AID=Not Implemented')
        end
    -- Decode Group 4 Clock-time and date
    elseif group_type == 4 and version_code == 0 then
        local function decode_mjd(mjd)
            local y_p = math.floor((mjd - 15078.2)/365.25)
            local m_p = math.floor((mjd - 14956.1 - math.floor(y_p * 365.25))/30.6001)
            local day = math.floor(mjd - 14956.1 - math.floor(y_p * 365.25) - math.floor(m_p * 30.6001))
            local k = 0
            if m_p == 15 or m_p == 15 then
                k = 1
            end
            local year = y_p + k
            local month = m_p - 1 - (k*12)
            return year, month, day
        end
        local hour = tvb:range(5,2):bitfield(7,5)
        local minute = tvb:range(6,2):bitfield(4, 6)
        t:add(f_g4_spare, tvb:range(2,2))
        t:add(f_g4_julian, tvb:range(2,4))
        t:add(f_g4_hour, tvb:range(5,2))
        t:add(f_g4_minute, tvb:range(6,2))
        t:add(f_g4_local_flag, tvb:range(6,2))
        t:add(f_g4_local_offset, tvb:range(6,2))
        local year, month, day = decode_mjd(tvb:range(2,4):bitfield(14, 17))
        pinfo.cols.info:append(' Y/M/D=' .. (1900 + year) .. '/' .. month .. '/' .. day)
        pinfo.cols.info:append(' ' .. hour .. 'h' .. minute .. 'm')
    -- Decode Group 5 Transparent data channels
    elseif group_type == 5 and version_code == 0 then
        t:add(f_g5_address, tvb:range(2,2))
        t:add(f_g5_data, tvb:range(4, 4))
        pinfo.cols.info:append(' channel=' .. tvb:range(2,2):bitfield(11, 5))
    -- Deocde Group 6 In-house applications
    elseif group_type == 6 and version_code == 0 then
        t:add(f_x_blk2, tvb:range(2,2))
        t:add(f_x_blk3, tvb:range(4,2))
        t:add(f_x_blk4, tvb:range(6,2))
    -- Decode Group 7 Radio Paging
    elseif group_type == 7 and version_code == 0 then
        t:add(f_g7_paging_ab, tvb:range(2,2))
        t:add(f_g7_address, tvb:range(2,2))
        t:add(f_g7_paging,tvb:range(4,4))
    -- Decode Group 8 Traffic Message Channel
    -- Based off of blackhat slides and not the standard spec
    elseif group_type == 8 and version_code == 0 then
        t:add(f_g8_t, tvb:range(2,2))
        t:add(f_g8_f, tvb:range(2,2))
        t:add(f_g8_dp, tvb:range(2,2))
        t:add(f_g8_d, tvb:range(4,2))
        t:add(f_g8_pn, tvb:range(4,2))
        t:add(f_g8_extent, tvb:range(4,2))
        t:add(f_g8_event, tvb:range(4,2))
        t:add(f_g8_location, tvb:range(6,2))
    -- Decode Group 9 Emergancy warning systems TODO
    elseif group_type == 9 and version_code == 0 then
        t:add(group09["address"], tvb:range(2,2))
        local address_code = tvb:range(2,2):bitfield(11, 15)
        if address_code == 0 then
            t:add(group09["spares1"], tvb:range(4,1))
            t:add(group09["org"], tvb:range(4,1))
            t:add(group09["eventchar"], tvb:range(5, 3))
        elseif address_code == 1 then
            t:add(group09["pssccc"], tvb:range(4,2))
            t:add(group09["portion"], tvb:range(4,2))
            t:add(group09["state_fips"], tvb:range(5,2))
            t:add(group09["country_fips"], tvb:range(6,2))
        elseif address_code == 2 then
            t:add(group09["hours"], tvb:range(4,2))
            t:add(group09["minutes"], tvb:range(4,2))
            t:add(group09["juliandate"], tvb:range(5,2))
            t:add(group09["hours_org"], tvb:range(6,2))
            t:add(group09["minutes_org"], tvb:range(6,2))
            t:add(group09["spares2"], tvb:range(6,2))
        elseif address_code == 3 then
            t:add(group09["id_start"], tvb:range(4,4))
        elseif address_code == 4 then
            t:add(group09["id_start"], tvb:range(4,4))
        elseif 5 <= address_code <= 29 then
            t:add(group09["data"], tvb:range(4,2))
            t:add(group09["data"], tvb:range(6,2))
        elseif address_code == 30 then
            t:add(group09["alt_freq"], tvb:range(4,1))
            t:add(group09["alt_freq"], tvb:range(5,1))
            t:add(group09["pi_eas"], tvb:range(6,2))
        elseif address_code == 31 then
            t:add(group09["pi_eas"], tvb:range(4,2))
            t:add(group09["pi_eas"], tvb:range(6,2))
        end
    -- Decode Group 10 Program Type Name
    elseif group_type == 10 and version_code == 0 then
        t:add(f_g10_flag, tvb:range(2,2))
        t:add(f_g10_spare, tvb:range(2,2))
        t:add(f_g10_address, tvb:range(2,2))
        t:add(f_g10_name, tvb:range(4,4))
        pinfo.cols.info:append(' PTY_EXT=' .. tvb:range(4,4):string())
    -- Decode Group 11 ODA
    elseif group_type == 11 and version_code == 0 then
        t:add(f_x_blk2, tvb:range(2,2))
        t:add(f_x_blk3, tvb:range(4,2))
        t:add(f_x_blk4, tvb:range(6,2))
    -- Decode Group 12 ODA
    elseif group_type == 12 and version_code == 0 then
        t:add(f_x_blk2, tvb:range(2,2))
        t:add(f_x_blk3, tvb:range(4,2))
        t:add(f_x_blk4, tvb:range(6,2))
    -- Decode Group 13 Enhanced Radio Paging
    elseif group_type == 13 and version_code == 0 then
        t:add(f_g13_info1, tvb:range(2,2))
        t:add(f_g13_sty, tvb:range(2,2))
        t:add(f_g13_info2, tvb:range(4,2))
        t:add(f_g13_info3, tvb:range(6,2))
    -- Decode Group 14 Enhanced Other Netowrks information
    elseif group_type == 14 and version_code == 0 then
        t:add(f_g14_tp, tvb:range(2,2))
        t:add(f_g14_variant, tvb:range(2,2))
        t:add(f_g14_info, tvb:range(4,2))
        t:add(f_g14_pi, tvb:range(6,2))
        pinfo.cols.dst:set(decode_PI(tvb:range(6,2):uint()))
    -- Decode Group 15 Fast basic tuning and switching information
    elseif group_type == 15 and version_code == 0 then
        t:add(f_g15_ta, tvb:range(2,2))
        t:add(f_g15_spare, tvb:range(2,2))
        t:add(f_g15_seg_addr, tvb:range(2,2))
        t:add(f_g15_name, tvb:range(4,4))
    end
end

