-- cp pac-nbd.lua ~/.config/wireshark/plugins/

set_plugin_info({
    version = "0.1.0",
    author = "Jonathan Dahan",
    repository = "https://github.com/reaktor/nbd-dissector"
})

local nbd_protocol = Proto("panasonic-nbd", "NBD broadcast")

local fragments = {}

local reassemble = function(id, packet_num, data)
    fragments[id] = fragments[id] or {}
    fragments[id][packet_num] = data:string()
    local file = table.concat(fragments[id], "")
    local bytes = ByteArray.new(file, true)
    return ByteArray.tvb(bytes, id)
end

nbd_protocol.fields = {
    ProtoField.uint8("nbd.msg_id", "msg_id", base.HEX, {
        [0x00] =  "Announce",
        [0x01] =  "Filelist",
        [0x02] =  "File Pkt",
        [0x05] =  "Status Request",
        [0x06] =  "File Trans St",
        [0x09] =  "File List Cached",
    }),
    ProtoField.uint8("nbd.session", "session"),
    ProtoField.uint8("nbd.server", "server"),
    ProtoField.uint8("nbd.flags", "flags", base.HEX),
    ProtoField.uint32("nbd.payload.filelist.length", "length", base.DEC),
    ProtoField.uint32("nbd.payload.filelist.crc", "crc", base.HEX),
    ProtoField.string("nbd.payload.filelist.file", "file"),
    ProtoField.uint16("nbd.payload.filelist.pkt_num", "pkt_num_list", base.DEC),
    ProtoField.uint16("nbd.payload.filelist.pkt_total", "pkt_total", base.DEC),
    ProtoField.uint32("nbd.payload.file_pkt.file_id", "file_id"),
    ProtoField.uint32("nbd.payload.file_pkt.pkt_num", "pkt_num_pkt", base.DEC),
    ProtoField.string("nbd.payload.file_pkt.raw", "raw"),
    ProtoField.uint8("nbd.payload.file_trans_st.tx_state", "tx_state", base.HEX, {
        [0x01] = "START",
        [0x02] = "PAUSE",
        [0x03] = "RESUME",
        [0x04] = "DONE",
        [0x05] = "ABORT",
    }),
}

function nbd_protocol.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end

    local msg_id = buffer(0,1)
    local session = buffer(1,1)
    local server = buffer(2,1)
    local flags = buffer(3,1)

    local field = function(name)
        for _, maybeField in ipairs(nbd_protocol.fields) do
            if type(maybeField) ~= "number" then
                if maybeField.name == name then
                    return maybeField
                end
            end
        end
    end

    local subtree = tree:add(nbd_protocol, "Panasonic NBD Broadcast" .. ", session: " .. session .. ", msg_id: " .. msg_id)
    subtree:add_le(field("msg_id"), msg_id)
    subtree:add_le(field("session"), session)
    subtree:add_le(field("server"), server)
    subtree:add_le(field("flags"), flags)

    local payload = subtree:add(nbd_protocol, buffer(16), "Payload")

    if msg_id:uint() == 0x01 then
        local filelist_length = buffer(4,4)
        payload:add_le(field("length"), filelist_length)
        local filelist_crc = buffer(8,4)
        payload:add_le(field("crc"), filelist_crc)

        local filelist_pkt_num = buffer(12, 2)
        payload:add_le(field("pkt_num_list"), filelist_pkt_num)
        local filelist_pkt_total = buffer(14, 2)
        payload:add_le(field("pkt_total"), filelist_pkt_total)
        local raw = buffer(16)
        payload:add(field("raw"), raw)

        local xml_tvb = reassemble(filelist_crc:uint(), filelist_pkt_num:le_uint(), raw)
        Dissector.get("xml"):call(xml_tvb, pinfo, tree)
    elseif msg_id:uint() == 0x02 then
        local file_id = buffer(4, 4):uint()
        payload:add(field("file_id"), file_id)
        local pkt_num = buffer(8, 4):le_uint()
        payload:add_le(field("pkt_num_pkt"), pkt_num)
        local raw = buffer(12)
        payload:add(field("raw"), raw)

        local json_tvb = reassemble(file_id, pkt_num + 1, raw)
        Dissector.get("json"):call(json_tvb, pinfo, tree)
    elseif msg_id:uint() == 0x06 then
        local tx_state = buffer(4,1):uint()
        payload:add_le(field("tx_state"), tx_state)
    end

    pinfo.cols.protocol = nbd_protocol.name
end

local udp_encap_table = DissectorTable.get("udp.port")
udp_encap_table:add(50131, nbd_protocol)
