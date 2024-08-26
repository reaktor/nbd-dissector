-- cp nbd.lua ~/.config/wireshark/plugins/

set_plugin_info({
    version = "0.1.0",
    author = "Jonathan Dahan",
    repository = "https://github.com/reaktor/nbd-dissector"
})

local nbd_protocol = Proto("panasonic-nbd", "NBD broadcast")

function nbd_protocol.init ()
    print ("(re-)initialise")
    Count = 0
    Filelist_xml = {}
end

local msg_ids = {
    [0x00] =  "Announce",
    [0x01] =  "Filelist",
    [0x02] =  "File Pkt",
    [0x05] =  "Status Request",
    [0x06] =  "File Trans St",
    [0x09] =  "File List Cached",
}
local f_msg_id = ProtoField.uint8("nbd.msg_id", "msg_id", base.HEX, msg_ids)
local f_session = ProtoField.uint8("nbd.session", "session")
local f_server = ProtoField.uint8("nbd.server", "server")
local f_flags = ProtoField.uint8("nbd.flags", "flags", base.HEX)

-- map from session_id to packet_num to packet_contents
local f_filelist_file = ProtoField.string("nbd.payload.filelist.file", "file")

local f_filelist_length = ProtoField.uint32("nbd.payload.filelist.length", "length", base.DEC)
local f_filelist_crc = ProtoField.uint32("nbd.payload.filelist.crc", "checksum", base.HEX)
local f_filelist_pkt_num = ProtoField.uint16("nbd.payload.filelist.pkt_num", "packet number", base.DEC)
local f_filelist_pkt_total = ProtoField.uint16("nbd.payload.filelist.pkt_total", "total packets", base.DEC)

local f_file_pkt_file_id = ProtoField.uint32("nbd.payload.file_pkt.file_id", "file id")
local f_file_pkt_pkt_num = ProtoField.uint32("nbd.payload.file_pkt.pkt_num", "packet number", base.DEC)
local f_file_pkt_raw = ProtoField.string("nbd.payload.file_pkt.raw", "raw text")

local tx_states = {
    [0x01] = "START",
    [0x02] = "PAUSE",
    [0x03] = "RESUME",
    [0x04] = "DONE",
    [0x05] = "ABORT",
}
local f_file_trans_st_tx_state = ProtoField.uint8("nbd.payload.file_trans_st.tx_state", "transfer state", base.HEX, tx_states)

nbd_protocol.fields = {
    f_msg_id, f_session, f_server, f_flags,
    f_filelist_length, f_filelist_crc, f_filelist_pkt_num, f_filelist_pkt_total, -- for filelist packets
    f_file_pkt_file_id, f_file_pkt_pkt_num, f_file_pkt_raw, f_filelist_file, -- for file pkt packets
    f_file_trans_st_tx_state -- for file_trans_st packets
}

local xml_dissector = Dissector.get("xml")
local f_filelist = ProtoField.none("nbd.filelist.filelist", "filelist")


function nbd_protocol.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end


    local msg_id = buffer(0,1)
    local session = buffer(1,1)

    local subtree = tree:add(nbd_protocol, "Panasonic NBD Broadcast" .. ", session: " .. session .. ", msg_id: " .. msg_id)
    subtree:add_le(f_msg_id, msg_id)
    subtree:add_le(f_session, session)
    subtree:add_le(f_server, buffer(2,1))
    subtree:add_le(f_flags, buffer(3,1))


    local payload = subtree:add(nbd_protocol, buffer(16), "Payload")

    if msg_id:uint() == 0x01 then
        local filelist_length = buffer(4,4)
        payload:add_le(f_filelist_length, filelist_length)
        local filelist_crc = buffer(8,4)
        payload:add_le(f_filelist_crc, filelist_crc)
        local filelist_pkt_num = buffer(12, 2)
        payload:add_le(f_filelist_pkt_num, filelist_pkt_num)
        local filelist_pkt_total = buffer(14, 2)
        payload:add_le(f_filelist_pkt_total, filelist_pkt_total)
        local raw = buffer(16)
        --payload:add_le(f_file_pkt_raw, raw)
        if Filelist_xml[session] == nil then
            Count = Count + 1
            Filelist_xml[session] = {
                [filelist_pkt_num] = raw
            }
        end
        print("created " .. Count .. " lists")
        print("session " .. session .. " pkt " .. filelist_pkt_num, Filelist_xml[session][filelist_pkt_num])

        local filelist_file = ""
        Filelist_xml[session][filelist_pkt_num] = raw
        if filelist_pkt_num == filelist_pkt_total then
            for key, value in pairs(Filelist_xml[session]) do
                print(key, value)
            end

            print("end of packet")
            --local filelist_file = ByteArray.new("filelist_file")
            print("sessiontable", Filelist_xml[session])
            for index, contents in ipairs(Filelist_xml[session]) do
                print("contents", contents)
                filelist_file = filelist_file .. contents
            end
            print(filelist_file)
            payload:add_le(f_filelist_file, filelist_file)
--            local file_tvb = ByteArray.tvb(filelist_file, "file")
--            nbd_protocol:call(file_tvb(0):tvb(), pinfo, subtree)
        end
    elseif msg_id:uint() == 0x02 then
        payload:add_le(f_file_pkt_file_id, buffer(4, 4))
        payload:add_le(f_file_pkt_pkt_num, buffer(8, 4))
        payload:add_le(f_file_pkt_raw, buffer(12, -1))
    elseif msg_id:uint() == 0x06 then
        local tx_state = buffer(4,1):uint()
        payload:add_le(f_file_trans_st_tx_state, tx_state)
    end

    pinfo.cols.protocol = nbd_protocol.name
end

local udp_encap_table = DissectorTable.get("udp.port")
udp_encap_table:add(50131, nbd_protocol)
