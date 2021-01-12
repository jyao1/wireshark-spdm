#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-tcp.h>

#define SPDM_PORT 2323
#define FRAME_HEADER_LEN 12

// RR == RequestResponse
#define GET_VERSION_REQUEST_RR_CODE          0x84
#define VERSION_RESPONSE_RR_CODE             0x04
#define GET_CAPABILITIES_REQUEST_RR_CODE     0xe1
#define CAPABILITIES_RESPONSE_RR_CODE        0x61
#define NEGOTIATE_ALGORITHMS_REQUEST_RR_CODE 0xe3
#define ALGORITHMS_RESPONSE_RR_CODE          0x63
#define GET_DIGESTS_REQUEST_RR_CODE          0x81
#define DIGESTS_RESPONSE_RR_CODE             0x01
#define GET_CERTIFICATE_REQUEST_RR_CODE      0x82
#define CERTIFICATE_RESPONSE_RR_CODE         0x02
#define CHALLENGE_REQUEST_RR_CODE            0x83
#define CHALLENGE_AUTH_RESPONSE_RR_CODE      0x03
#define GET_MEASUREMENTS_REQUEST_RR_CODE     0xe0
#define MEASUREMENTS_RESPONSE_RR_CODE        0x60
#define ERROR_RESPONSE_RR_CODE               0x7f
#define RESPOND_IF_READY_REQUEST_RR_CODE     0xff
#define VENDOR_DEFINED_REQUEST_RR_CODE       0xfe
#define VENDOR_DEFINED_RESPONSE_RR_CODE      0x7e
#define KEY_EXCHANGE_REQUEST_RR_CODE         0xe4
#define KEY_EXCHANGE_RESPONSE_RR_CODE        0x64
#define FINISH_REQUEST_RR_CODE               0xe5
#define FINISH_RESPONSE_RR_CODE              0x65
#define PSK_EXCHANGE_REQUEST_RR_CODE         0xe6
#define PSK_EXCHANGE_RESPONSE_RR_CODE        0x66
#define PSK_FINISH_REQUEST_RR_CODE           0xe7
#define PSK_FINISH_RESPONSE_RR_CODE          0x67
#define HEARTBEAT_REQUEST_RR_CODE            0xe8
#define HEARTBEAT_ACK_RESPONSE_RR_CODE       0x68
#define KEY_UPDATE_REQUEST_RR_CODE           0xe9
#define KEY_UPDATE_ACK_RESPONSE_RR_CODE      0x69
#define GET_ENCAPSULATED_REQUEST_RR_CODE     0xea
#define ENCAPSULATED_RESPONSE_RR_CODE        0x6a
#define DELIVER_ENCAPSULATED_REQUEST_RR_CODE 0xeb
#define ENCAPSULATED_ACK_RESPONSE_RR_CODE    0x6b
#define END_SESSION_REQUEST_RR_CODE          0xec
#define END_SESSION_ACK_RESPONSE_RR_CODE     0x6c


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
// GET_VERSION request and VERSION response messages
static int hf_spdm_VersionNumberEntryCount = -1;
static int hf_spdm_VersionNumberEntry = -1;
// static int hf_spdm_MajorVersion = -1;
// static int hf_spdm_MinorVersion = -1;
// static int hf_spdm_UpdateVersionNumber = -1;
// static int hf_spdm_Alpha = -1;
// GET_CAPABILITIES request and CAPABILITIES response messages
static int hf_spdm_CTExponent = -1;
static int hf_spdm_CapabilitiesFlags = -1; // add bit
// NEGOTIATE_ALGORITHMS request and ALGORITHMS response messages
static int hf_spdm_ALG_Length = -1;
static int hf_spdm_ALG_MeasurementSpecification = -1;
static int hf_spdm_ALG_BaseAsymAlgo  = -1;
static int hf_spdm_ALG_BaseHashAlgo  = -1;
static int hf_spdm_ALG_ExtAsymCount  = -1;
static int hf_spdm_ALG_ExtHashCount = -1;
static int hf_spdm_ALG_ExtAsym = -1;
static int hf_spdm_ALG_ExtHash = -1;
static int hf_spdm_ALG_ReqAlgStruct = -1;
static int hf_spdm_ALG_MeasurementSpecificationSel = -1;
static int hf_spdm_ALG_MeasurementHashAlgo = -1;
static int hf_spdm_ALG_BaseAsymSel = -1;
static int hf_spdm_ALG_BaseHashSel = -1;
static int hf_spdm_ALG_ExtAsymSelCount = -1;
static int hf_spdm_ALG_ExtHashSelCount = -1;
static int hf_spdm_ALG_ExtAsymSel = -1;
static int hf_spdm_ALG_ExtHashSel = -1;
static int hf_spdm_ALG_RespAlgStruct = -1;

//  GET_DIGESTS request and DIGESTS response messages
static int hf_spdm_digests_digest = -1;

static struct {
    gint spdm;
} spdm_ett;

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

static void
dissect_get_version_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM GET VERSION REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}


static void
dissect_version_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    guint8 index;
    guint8 VersionNumberEntryCount;
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM VERSION RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 2;
    VersionNumberEntryCount = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(subtree, hf_spdm_VersionNumberEntryCount, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    for (index = 0; index < VersionNumberEntryCount; index ++) {
        proto_tree_add_item(subtree, hf_spdm_VersionNumberEntry, tvb, offset, 2, ENC_BIG_ENDIAN);
        if ((index + 1) == VersionNumberEntryCount) {
            break;
        } 
        offset += 2;
    }     
}

static void
dissect_get_capabilities_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM GET CAPABILITIES REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_spdm_CTExponent, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 3;
    proto_tree_add_item(subtree, hf_spdm_CapabilitiesFlags, tvb, offset, 4, ENC_BIG_ENDIAN);
}

static void
dissect_capabilities_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM CAPABILITIES RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_spdm_CTExponent, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 3;
    proto_tree_add_item(subtree, hf_spdm_CapabilitiesFlags, tvb, offset, 4, ENC_BIG_ENDIAN);
}

static void
dissect_negotiate_algorithms_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM NEGOTIATE ALGORITHMS REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_ALG_Length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_spdm_ALG_MeasurementSpecification, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_spdm_ALG_BaseAsymAlgo, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(subtree, hf_spdm_ALG_BaseHashAlgo, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 16;
    guint8 ExtAsymCount = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(subtree, hf_spdm_ALG_ExtAsymCount, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    guint8 ExtHashCount = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(subtree, hf_spdm_ALG_ExtHashCount, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 3;
    if (ExtAsymCount != 0) {
        proto_tree_add_item(subtree, hf_spdm_ALG_ExtAsym, tvb, offset, 4 * ExtAsymCount, ENC_BIG_ENDIAN);
        offset += 4 * ExtAsymCount;
    }
    if (ExtHashCount != 0) {
        proto_tree_add_item(subtree, hf_spdm_ALG_ExtHash, tvb, offset, 4 * ExtHashCount, ENC_BIG_ENDIAN);
        offset += 4 * ExtHashCount;
    }
    
    proto_tree_add_item(subtree, hf_spdm_ALG_ReqAlgStruct, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_algorithms_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM ALGORITHMS RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_ALG_Length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_spdm_ALG_MeasurementSpecificationSel, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_spdm_ALG_MeasurementHashAlgo, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(subtree, hf_spdm_ALG_BaseAsymSel, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(subtree, hf_spdm_ALG_BaseHashSel, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 16;
    guint8 ExtAsymSelCount = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(subtree, hf_spdm_ALG_ExtAsymSelCount, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    guint8 ExtHashSelCount = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(subtree, hf_spdm_ALG_ExtHashSelCount, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 3;
    if (ExtAsymSelCount != 0) {
        proto_tree_add_item(subtree, hf_spdm_ALG_ExtAsymSel, tvb, offset, 4 * ExtAsymSelCount, ENC_BIG_ENDIAN);
        offset += 4 * ExtAsymSelCount;
    }
    if (ExtHashSelCount != 0) {
        proto_tree_add_item(subtree, hf_spdm_ALG_ExtHashSel, tvb, offset, 4 * ExtHashSelCount, ENC_BIG_ENDIAN);
        offset += 4 * ExtHashSelCount;
    }

    proto_tree_add_item(subtree, hf_spdm_ALG_RespAlgStruct, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_get_digests_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM GET DIGESTS REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_digests_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM DIGESTS RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_get_certificate_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM GET CERTIFICATE REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_certificate_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM CERTIFICATE RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_get_challenge_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM GET CHANLLENGE REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_challenge_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM CHANLLENGE_AUTH RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_get_mesurements_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM GET MEASUREMENTS REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_mesurements_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM MEASUREMENTS RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_error_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM ERROR RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_respond_if_ready_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM RESPOND IF READY REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_vendor_defined_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM VENDOR DEFINED REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_vendor_defined_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM VENDOR DEFINED RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_key_exchange_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM KEY EXCHANGE REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_key_exchange_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM KEY EXCHANGE RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_finish_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM FINISH REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_finish_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM FINISH RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_psk_exchange_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM PSK EXCHANGE REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_psk_exchange_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM PSK EXCHANGE RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_psk_finish_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM PSK FINISH REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_psk_finish_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM PSK FINISH RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_heartbeat_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM HEARTBEAT REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_heartbeat_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM HEARTBEAT RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_key_update_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM KEY UPDATE REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_key_update_ack_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM KEY UPDATE ACK RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_get_encapsulated_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM GET ENCAPSULATED REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_encapsulated_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM ENCAPSULATED RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_deliver_encapsulated_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM DELIVER ENCAPSULATED REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_encapsulated_ack_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM ENCAPSULATED ACK RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_end_session_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM END SESSION REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_end_session_ack_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, guint32 offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM END SESSION ACK RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_BIG_ENDIAN);
}



/* This method dissects fully reassembled messages */
static int
dissect_spdm_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{  
    guint32 offset = 0;
    guint32 command;
    guint32 transporttype;
    guint32 mesgsize;
    unsigned RequestResponseCode;

    proto_item* item;
    proto_tree* subtree;
    
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SPDM");
    col_clear(pinfo->cinfo, COL_INFO);
    col_append_ports(pinfo->cinfo, COL_INFO, PT_TCP, pinfo->srcport, pinfo->destport);
    
    item = proto_tree_add_item(tree, proto_spdm, tvb, 0, -1, ENC_NA);
    
    command = tvb_get_guint32(tvb, 0, ENC_BIG_ENDIAN);
    transporttype = tvb_get_guint32(tvb, 4, ENC_BIG_ENDIAN);
    mesgsize = tvb_get_guint32(tvb, 8, ENC_BIG_ENDIAN);

    proto_item_append_text(item, ", Command: %s", val_to_str(command, packetCommand, "Unknown (0x%08x)"));
    proto_item_append_text(item, ", TransportType: %s", val_to_str(transporttype, packetTransportType, "Unknown (0x%08x)"));
    proto_item_append_text(item, ", Size：0x%08x", mesgsize);
    
    subtree = proto_item_add_subtree(item, spdm_ett.spdm);

    if (pinfo->destport == 2323) {
        proto_tree_add_item(subtree, hf_spdm_TransmitCommand, tvb, 0, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(subtree, hf_spdm_TransmitTransportType, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(subtree, hf_spdm_TransmitSize, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4; 
    } else {
        proto_tree_add_item(subtree, hf_spdm_RecieveCommand, tvb, 0, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(subtree, hf_spdm_RecieveTransportType, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(subtree, hf_spdm_RecieveSize, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (command == 0x00000001) {
        proto_tree_add_item(subtree, hf_spdm_MCTPMessageType, tvb, offset, 1, ENC_BIG_ENDIAN);
        guint MCTPMessageType = tvb_get_guint8(tvb, 12);
        offset += 1;
        if (MCTPMessageType == 0x05) {
            RequestResponseCode = tvb_get_guint8(tvb, 14);
            switch(RequestResponseCode) {
                case GET_VERSION_REQUEST_RR_CODE:
                    dissect_get_version_request_message(tvb, pinfo, subtree, offset);
                    break;
                case VERSION_RESPONSE_RR_CODE:
                    dissect_version_response_message(tvb, pinfo, subtree, offset);
                    break;
                case GET_CAPABILITIES_REQUEST_RR_CODE:
                    dissect_get_capabilities_request_message(tvb, pinfo, subtree, offset);
                    break;
                case CAPABILITIES_RESPONSE_RR_CODE:
                    dissect_capabilities_response_message(tvb, pinfo, subtree, offset);
                    break;
                case NEGOTIATE_ALGORITHMS_REQUEST_RR_CODE:
                    dissect_negotiate_algorithms_request_message(tvb, pinfo, subtree, offset);
                    break;
                case ALGORITHMS_RESPONSE_RR_CODE:
                    dissect_algorithms_response_message(tvb, pinfo, subtree, offset);
                    break;
                case GET_DIGESTS_REQUEST_RR_CODE:
                    dissect_get_digests_request_message(tvb, pinfo, subtree, offset);
                    break;
                case DIGESTS_RESPONSE_RR_CODE:
                    dissect_digests_response_message(tvb, pinfo, subtree, offset);
                    break;
                case GET_CERTIFICATE_REQUEST_RR_CODE:
                    dissect_get_certificate_request_message(tvb, pinfo, subtree, offset);
                    break;
                case CERTIFICATE_RESPONSE_RR_CODE:
                    dissect_certificate_response_message(tvb, pinfo, subtree, offset);
                    break;
                case CHALLENGE_REQUEST_RR_CODE:
                    dissect_get_challenge_request_message(tvb, pinfo, subtree, offset);
                    break;
                case CHALLENGE_AUTH_RESPONSE_RR_CODE:
                    dissect_challenge_response_message(tvb, pinfo, subtree, offset);
                    break;
                case GET_MEASUREMENTS_REQUEST_RR_CODE:
                    dissect_get_mesurements_request_message(tvb, pinfo, subtree, offset);
                    break;
                case MEASUREMENTS_RESPONSE_RR_CODE :
                    dissect_mesurements_response_message(tvb, pinfo, subtree, offset);
                    break;
                case ERROR_RESPONSE_RR_CODE:
                    dissect_error_response_message(tvb, pinfo, subtree, offset);
                    break;
                case RESPOND_IF_READY_REQUEST_RR_CODE:
                    dissect_respond_if_ready_request_message(tvb, pinfo, subtree, offset);
                    break;
                case VENDOR_DEFINED_REQUEST_RR_CODE:
                    dissect_vendor_defined_request_message(tvb, pinfo, subtree, offset);
                    break;
                case VENDOR_DEFINED_RESPONSE_RR_CODE:
                    dissect_vendor_defined_response_message(tvb, pinfo, subtree, offset);
                    break;
                case KEY_EXCHANGE_REQUEST_RR_CODE:
                    dissect_key_exchange_request_message(tvb, pinfo, subtree, offset);
                    break;
                case KEY_EXCHANGE_RESPONSE_RR_CODE:
                    dissect_key_exchange_response_message(tvb, pinfo, subtree, offset);
                    break;
                case FINISH_REQUEST_RR_CODE:
                    dissect_finish_request_message(tvb, pinfo, subtree, offset);
                    break;
                case FINISH_RESPONSE_RR_CODE:
                    dissect_finish_response_message(tvb, pinfo, subtree, offset);
                    break;
                case PSK_EXCHANGE_REQUEST_RR_CODE:
                    dissect_psk_exchange_request_message(tvb, pinfo, subtree, offset);
                    break;
                case PSK_EXCHANGE_RESPONSE_RR_CODE:
                    dissect_psk_exchange_response_message(tvb, pinfo, subtree, offset);
                    break;
                case PSK_FINISH_REQUEST_RR_CODE:
                    dissect_psk_finish_request_message(tvb, pinfo, subtree, offset);
                    break;
                case PSK_FINISH_RESPONSE_RR_CODE:
                    dissect_psk_finish_response_message(tvb, pinfo, subtree, offset);
                    break;
                case HEARTBEAT_REQUEST_RR_CODE:
                    dissect_heartbeat_request_message(tvb, pinfo, subtree, offset);
                    break;
                case HEARTBEAT_ACK_RESPONSE_RR_CODE:
                    dissect_heartbeat_response_message(tvb, pinfo, subtree, offset);
                    break;
                case KEY_UPDATE_REQUEST_RR_CODE:
                    dissect_key_update_request_message(tvb, pinfo, subtree, offset);
                    break;
                case KEY_UPDATE_ACK_RESPONSE_RR_CODE:
                    dissect_key_update_ack_response_message(tvb, pinfo, subtree, offset);
                    break;
                case GET_ENCAPSULATED_REQUEST_RR_CODE:
                    dissect_get_encapsulated_request_message(tvb, pinfo, subtree, offset);
                    break;
                case ENCAPSULATED_RESPONSE_RR_CODE:
                    dissect_encapsulated_response_message(tvb, pinfo, subtree, offset);
                    break;
                case DELIVER_ENCAPSULATED_REQUEST_RR_CODE:
                    dissect_deliver_encapsulated_request_message(tvb, pinfo, subtree, offset);
                    break;
                case ENCAPSULATED_ACK_RESPONSE_RR_CODE:
                    dissect_encapsulated_ack_response_message(tvb, pinfo, subtree, offset);
                    break;
                case END_SESSION_REQUEST_RR_CODE:
                    dissect_end_session_request_message(tvb, pinfo, subtree, offset);
                    break;
                case END_SESSION_ACK_RESPONSE_RR_CODE:
                    dissect_end_session_ack_response_message(tvb, pinfo, subtree, offset);
                    break;
                default:
                    break;
            }
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
        { &hf_spdm_VersionNumberEntryCount,
            { "VersionNumberEntryCount", "spdm.versionRes.VersionNumberEntryCount",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_VersionNumberEntry,
            { "VersionNumberEntry", "spdm.versionRes.VersionNumberEntry",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        // { &hf_spdm_MajorVersion,
        //     { "MajorVersion", "spdm.versionRes.MajorVersion",
        //     FT_BYTES, BASE_HEX,
        //     NULL, 0x0,
        //     NULL, HFILL }
        // },
        // { &hf_spdm_MinorVersion,
        //     { "MinorVersion", "spdm.versionRes.MinorVersion",
        //     FT_BYTES, BASE_HEX,
        //     NULL, 0x0,
        //     NULL, HFILL }
        // },
        // { &hf_spdm_UpdateVersionNumber,
        //     { "UpdateVersionNumber", "spdm.versionRes.UpdateVersionNumber",
        //     FT_BYTES, BASE_HEX,
        //     NULL, 0x0,
        //     NULL, HFILL }
        // },
        // { &hf_spdm_Alpha,
        //     { "Alpha", "spdm.versionRes.Alpha",
        //     FT_BYTES, BASE_HEX,
        //     NULL, 0x0,
        //     NULL, HFILL }
        // },
        { &hf_spdm_CTExponent,
            { "CTExponent", "spdm.CTExponent",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_CapabilitiesFlags,
            { "Flags", "spdm.Flags",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_ALG_Length,
            { "Length", "spdm.Length",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_ALG_MeasurementSpecification,
            { "MeasurementSpecification", "spdm.MeasurementSpecification",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_ALG_BaseAsymAlgo,
            { "BaseAsymAlgo", "spdm.BaseAsymAlgo",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_ALG_BaseHashAlgo,
            { "BaseHashAlgo", "spdm.BaseHashAlgo",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_ALG_ExtAsymCount,
            { "ExtAsymCount", "spdm.ExtAsymCount",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_ALG_ExtHashCount,
            { "ExtHashCount", "spdm.ExtHashCount",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_ALG_ExtAsym,
            { "ExtAsym", "spdm.ExtAsym",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_ALG_ExtHash,
            { "ExtHash", "spdm.ExtHash",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_ALG_ReqAlgStruct,
            { "ReqAlgStruct", "spdm.ReqAlgStruct",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_ALG_MeasurementSpecificationSel,
            { "MeasurementSpecificationSel", "spdm.MeasurementSpecificationSel",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_ALG_MeasurementHashAlgo,
            { "MeasurementHashAlgo", "spdm.MeasurementHashAlgo",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_ALG_BaseAsymSel,
            { "BaseAsymSel", "spdm.BaseAsymSel",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_ALG_BaseHashSel,
            { "BaseHashSel", "spdm.BaseHashSel",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_ALG_ExtAsymSelCount,
            { "ExtAsymSelCount", "spdm.ExtAsymSelCount",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_ALG_ExtHashSelCount,
            { "ExtHashSelCount", "spdm.ExtHashSelCount",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_ALG_ExtAsymSel,
            { "ExtAsymSel", "spdm.ExtAsymSel",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_ALG_ExtHashSel,
            { "ExtHashSel", "spdm.ExtHashSel",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_ALG_RespAlgStruct,
            { "RespAlgStruct", "spdm.RespAlgStruct",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
    };



    proto_spdm = proto_register_protocol (
    "SPDM",          /* name        */
    "SPDM",          /* short_name  */
    "spdm"           /* filter_name */
    );

     {
        gint *ett[sizeof(spdm_ett) / sizeof(gint)];
        unsigned i;
        for (i = 0; i < array_length(ett); i++) {
            ett[i] = (gint *)&spdm_ett + i;
            *ett[i] = -1;
        }
        proto_register_subtree_array(ett, array_length(ett));
    }

    proto_register_field_array(proto_spdm, hf, array_length(hf));
}

void
proto_reg_handoff_spdm(void)
{
    static dissector_handle_t spdm_handle;

    spdm_handle = create_dissector_handle(dissect_spdm, proto_spdm);
    dissector_add_uint("tcp.port", SPDM_PORT, spdm_handle);
}
