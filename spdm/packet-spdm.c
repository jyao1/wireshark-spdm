#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-tcp.h>

#define SPDM_PORT 2323
#define FRAME_HEADER_LEN 12

static int proto_spdm = -1;
static int hf_spdm_TransmitCommand = -1;
static int hf_spdm_TransmitTransportType = -1;
static int hf_spdm_TransmitSize = -1;
static int hf_spdm_TransmitBuffer = -1;
static int hf_spdm_RecieveCommand = -1;
static int hf_spdm_RecieveTransportType = -1;
static int hf_spdm_RecieveSize = -1;

static int hf_spdm_MCTPMessageType = -1;

static int hf_spdm_SPDMVersion = -1;
static int hf_spdm_RequestResponseCode = -1;
static int hf_spdm_Param1 = -1;
static int hf_spdm_Param2 = -1;


static gint ett_spdm = -1;

static const value_string packetCommand[] = {
    { 0x0001, "NORMAL" },
    { 0xFFFE, "STOP" },
    { 0xFFFF, "UNKOWN" },
    { 0xDEAD, "TEST" }
};

static const value_string packetTransportType[] = {
    { 0x01, "MCTP" },
    { 0x02, "PCI_DOE" },
};


/* This method dissects fully reassembled messages */
static int
dissect_spdm_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{  
    gint offset = 0;
    guint32 command = tvb_get_guint32(tvb, 0, ENC_BIG_ENDIAN);
    guint32 transporttype = tvb_get_guint32(tvb, 4, ENC_BIG_ENDIAN);
    guint32 mesgsize = tvb_get_guint32(tvb, 8, ENC_BIG_ENDIAN);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SPDM");
    col_clear(pinfo->cinfo, COL_INFO);
    col_append_ports(pinfo->cinfo, COL_INFO, PT_TCP, pinfo->srcport, pinfo->destport);
    
    proto_item* ti = proto_tree_add_item(tree, proto_spdm, tvb, 0, -1, ENC_NA);
    

    proto_item_append_text(ti, " Command: %s",
        val_to_str(command, packetCommand, "Unknown (0x%02x)"));
    proto_item_append_text(ti, " TransportType: %s",
        val_to_str(transporttype, packetTransportType, "Unknown (0x%02x)"));
    proto_item_append_text(ti, " Size：0x%02x", mesgsize);
    
    proto_tree* spdm_tree = proto_item_add_subtree(ti, ett_spdm);

    if (pinfo->destport == 2323) {
        proto_tree_add_item(spdm_tree, hf_spdm_TransmitCommand, tvb, 0, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(spdm_tree, hf_spdm_TransmitTransportType, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(spdm_tree, hf_spdm_TransmitSize, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4; 
    } else {
        proto_tree_add_item(spdm_tree, hf_spdm_RecieveCommand, tvb, 0, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(spdm_tree, hf_spdm_RecieveTransportType, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(spdm_tree, hf_spdm_RecieveSize, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    if (command == 0x00000001) {
        proto_tree_add_item(spdm_tree, hf_spdm_MCTPMessageType, tvb, offset, 1, ENC_BIG_ENDIAN);
        guint MCTPMessageType = tvb_get_guint8(tvb, 12);
        offset += 1;
        if (MCTPMessageType == 0x05) {
            proto_tree_add_item(spdm_tree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(spdm_tree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(spdm_tree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(spdm_tree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        }
        // else if (MCTPMessageType == 0x06) {
        //     continue;
        // }
    }
       
    return tvb_captured_length(tvb);
}

/* determine PDU length of protocol spdm */
static guint32
get_spdm_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return (guint32)tvb_get_ntohl(tvb, offset + 8) + FRAME_HEADER_LEN; /* e.g. length is at offset 4 */
}

/* The main dissecting routine */
static int
dissect_spdm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{   
    if (tree) {
        tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
                     get_spdm_message_len, dissect_spdm_message, data);
    }
    
    return tvb_captured_length(tvb);
}

void
proto_register_spdm(void)
{

      static hf_register_info hf[] = {
        { &hf_spdm_TransmitCommand,
            { "Platform Port Transmit Command", "spdm.TransmitCommand",
            FT_UINT32, BASE_HEX,
            VALS(packetCommand), 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_TransmitTransportType,
            { "Platform Port Transmit TransportType", "spdm.TransmitTransportType",
            FT_UINT32, BASE_HEX,
            VALS(packetTransportType), 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_TransmitSize,
            { "Platform Port Transmit Size", "spdm.TransmitSize",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_spdm_RecieveCommand,
            { "Platform Port Recieve Command", "spdm.RecieveCommand",
            FT_UINT32, BASE_HEX,
            VALS(packetCommand), 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_RecieveTransportType,
            { "Platform Port Recieve TransportType", "spdm.RecieveTransportType",
            FT_UINT32, BASE_HEX,
            VALS(packetTransportType), 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_RecieveSize,
            { "Platform Port Recieve Size", "spdm.RecieveSize",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        
        { &hf_spdm_MCTPMessageType,
            { "MCTP Message Type", "spdm.MCTPMessageType",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_SPDMVersion,
            { "SPDMVersion", "spdm.SPDMVersion",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_RequestResponseCode,
            { "RequestResponseCode", "spdm.RequestResponseCode",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_Param1,
            { "Param1", "spdm.Param1",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_Param2,
            { "Param2", "spdm.Param2",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
    };

    proto_spdm = proto_register_protocol (
    "SPDM Message", /* name        */
    "SPDM",          /* short_name  */
    "spdm"           /* filter_name */
    );

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_spdm,
    };

    
    proto_register_field_array(proto_spdm, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_spdm(void)
{
    static dissector_handle_t spdm_handle;

    spdm_handle = create_dissector_handle(dissect_spdm, proto_spdm);
    dissector_add_uint("tcp.port", SPDM_PORT, spdm_handle);
}
