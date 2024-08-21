-- cp nbd.lua ${XDG_CONFIG_HOME:-${HOME}/.config}/wireshark/plugins/
local nbd_protocol = Proto("pac-nbd", "NBD broadcast");

local f_msg_id = ProtoField.string("nbd.msg_id")
local f_session = ProtoField.string("nbd.session")
local f_server = ProtoField.string("nbd.server")
local f_flags = ProtoField.string("nbd.flags")
local f_raw = ProtoField.string("nbd.raw")

-- Filelist
-- MSG ID = 0x01, SESSION, SERVER, FLAGS
-- LENGTH x4
-- CRC x4
-- PKT NUM x3, PKT TOTAL

-- File Pkt
-- MSG ID = 0x02, SESSION, SERVER, FLAGS

nbd_protocol.fields = { f_msg_id, f_session, f_server, f_flags}

local data_dis = Dissector.get("data")

function nbd_protocol.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end

    local msg_id = buffer(0,1):uint()
    local msg_id_labels = {
        [0x01] = "Filelist",
        [0x02] = "File Pkt"
    }

    if msg_id > #msg_id_labels then return end

    local subtree = tree:add(nbd_protocol, "Panasonic NBD Broadcast")
    subtree:add(f_msg_id, msg_id_labels[msg_id])


    local session = buffer(1,2):uint()
    subtree:add(f_session, session)

    local server = buffer(2,3):uint()
    subtree:add(f_server, server)

    local flags = buffer(3,4):uint()
    subtree:add(f_flags, flags)

    pinfo.cols.protocol = nbd_protocol.name
end

local udp_encap_table = DissectorTable.get("udp.port")
udp_encap_table:add(50131, nbd_protocol)
