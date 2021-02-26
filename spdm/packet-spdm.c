#pragma warning(disable:4005)
#pragma warning(disable:4022)
#pragma warning(disable:4090)
#pragma warning(disable:4189)

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-tcp.h>
#include <openspdm/Tool/SpdmDump/SpdmDump.h>
#include <openspdm/Include/IndustryStandard/Spdm.h>

#define SPDM_PORT 2323
#define FRAME_HEADER_LEN 12

guint RecordMeassageNum[1024];
gint RecordMessageIndex = 0;

char PskBuffer[] = "5465737450736b4461746100";
char DheSecretBuffer[] = "c7ac17ee29b6a4f84e978223040b7eddff792477a6f7fc0f51faa553fee58175";

guint8  ChallengeRequestParam2;
guint8  MesurementsRequestParam1;
guint8  KeyExchangeRequestParam1;
guint8  PskExchangeRequestParam1;
guint32 SignatureSize;
guint32 HashSize;
guint32 DheKeySize;
guint32 CapabilitiesFlags;

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
static int hf_spdm_Reserved = -1;
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
// GET_CERTIFICATE request and CERTIFICATE response messages
static int hf_spdm_Cert_Offset = -1;
static int hf_spdm_Cert_Length = -1;
static int hf_spdm_Cert_PortionLength = -1;
static int hf_spdm_Cert_RemainderLength = -1;
static int hf_spdm_Cert_CertChain = -1;

//  GET_DIGESTS request and DIGESTS response messages
static int hf_spdm_digests_digest = -1;

// CHALLENGE request and CHALLENGE_AUTH response messages
static int hf_spdm_challenge_Nonce = -1;
static int hf_spdm_challenge_CertChainHash = -1;
static int hf_spdm_challenge_MeasurementSummaryHash = -1;
static int hf_spdm_challenge_OpaqueLength = -1;
static int hf_spdm_challenge_OpaqueData = -1;
static int hf_spdm_challenge_Signature = -1;

// GET_MEASUREMENTS request and MEASUREMENTS response messages
static int hf_spdm_measurements_Nonce = -1;
static int hf_spdm_measurements_SlotIDParam = -1;
static int hf_spdm_measurements_NumberOfBlocks = -1;
static int hf_spdm_measurements_MeasurementRecordLength = -1;
static int hf_spdm_measurements_MeasurementRecord = -1;
static int hf_spdm_measurements_OpaqueLength = -1;
static int hf_spdm_measurements_OpaqueData = -1;
static int hf_spdm_measurements_Signature = -1;

// ERROR response message
static int hf_spdm_ExtendedErrorData = -1;

// VENDOR_DEFINED_REQUEST request message
static int hf_spdm_vendor_defined_StandardID = -1;
static int hf_spdm_vendor_defined_Len = -1;
static int hf_spdm_vendor_defined_VendorID = -1;
static int hf_spdm_vendor_defined_ReqLength = -1;
static int hf_spdm_vendor_defined_ReqPayload = -1;
static int hf_spdm_vendor_defined_RespLength = -1;
static int hf_spdm_vendor_defined_RespPayload = -1;

// KEY_EXCHANGE request and KEY_EXCHANGE_RSP response messages
static int hf_spdm_key_exchange_ReqSessionID = -1;
static int hf_spdm_key_exchange_RandomData = -1;
static int hf_spdm_key_exchange_ExchangeData = -1;
static int hf_spdm_key_exchange_OpaqueDataLength = -1;
static int hf_spdm_key_exchange_OpaqueData = -1;
static int hf_spdm_key_exchange_RspSessionID = -1;
static int hf_spdm_key_exchange_MutAuthRequested = -1;
static int hf_spdm_key_exchange_SlotIDParam = -1;
static int hf_spdm_key_exchange_MeasurementSummaryHash = -1;
static int hf_spdm_key_exchange_Signature = -1;
static int hf_spdm_key_exchange_ResponderVerifyData = -1;

// FINISH request and FINISH_RSP response messages
static int hf_spdm_finish_Signature = -1;
static int hf_spdm_finish_RequesterVerifyData = -1;
static int hf_spdm_finish_ResponderVerifyData = -1;

//  PSK_EXCHANGE request and PSK_EXCHANGE_RSP response messages
static int hf_spdm_psk_exchange_ReqSessionID = -1;
static int hf_spdm_psk_exchange_P = -1;
static int hf_spdm_psk_exchange_R = -1;
static int hf_spdm_psk_exchange_OpaqueDataLength = -1;
static int hf_spdm_psk_exchange_PSKHint = -1;
static int hf_spdm_psk_exchange_RequesterContext = -1;
static int hf_spdm_psk_exchange_OpaqueData = -1;
static int hf_spdm_psk_exchange_RepSessionID = -1;
static int hf_spdm_psk_exchange_Q = -1;
static int hf_spdm_psk_exchange_MeasurementSummaryHash = -1;
static int hf_spdm_psk_exchange_ResponderContext = -1;
static int hf_spdm_psk_exchange_ResponderVerifyData = -1;

// PSK_FINISH request and PSK_FINISH_RSP response messages
static int hf_spdm_psk_finish_RequesterVerifyData = -1;

// GET_ENCAPSULATED_REQUEST request and ENCAPSULATED_REQUEST response messages
static int hf_spdm_EncapsulatedRequest = -1;

// DELIVER_ENCAPSULATED_RESPONSE request and ENCAPSULATED_RESPONSE_ACK response messages
static int hf_spdm_EncapsulatedResponse = -1;

static int hf_spdm_SessionId = -1;
static int hf_spdm_SequenceNum = -1;
static int hf_spdm_SequenceNumSize = -1;
static int hf_spdm_MessageSize = -1;

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

static guint32 
GetSignatureSize(guint32 BaseAsymAlgo) {
    switch (BaseAsymAlgo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        return 256;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        return 384;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        return 512;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        return 32 * 2;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        return 48 * 2;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        return 66 * 2;
    }
    return 0;
}

static guint32 
GetHashSize(guint32 BaseHashAlgo) {
    switch (BaseHashAlgo) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
        return 32;
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
        return 48;
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
        return 64;
    }
    return 0;
}

static guint32 
GetSpdmDheKeySize(guint32 DHENamedGroup) {
    switch (DHENamedGroup) {
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
        return 256;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
        return 384;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
        return 512;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
        return 32 * 2;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
        return 48 * 2;
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
        return 66 * 2;
    }
    return 0;
}

static void
dissect_get_version_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM GET VERSION REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}


static void
dissect_version_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    guint8 index;
    guint8 VersionNumberEntryCount;
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM VERSION RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Reserved, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    VersionNumberEntryCount = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(subtree, hf_spdm_VersionNumberEntryCount, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    for (index = 0; index < VersionNumberEntryCount; index ++) {
        proto_tree_add_item(subtree, hf_spdm_VersionNumberEntry, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        if ((index + 1) == VersionNumberEntryCount) {
            break;
        } 
        offset += 2;
    }     
}

static void
dissect_get_capabilities_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM GET CAPABILITIES REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Reserved, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_CTExponent, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_spdm_CapabilitiesFlags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void
dissect_capabilities_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM CAPABILITIES RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Reserved, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_CTExponent, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    CapabilitiesFlags = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_spdm_CapabilitiesFlags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

static void
dissect_negotiate_algorithms_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    gint    ReqAlgStructLen;
    guint8  ExtAsymCount;
    guint8  ExtHashCount;
    

    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM NEGOTIATE ALGORITHMS REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_ALG_Length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_spdm_ALG_MeasurementSpecification, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Reserved, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_ALG_BaseAsymAlgo, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(subtree, hf_spdm_ALG_BaseHashAlgo, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(subtree, hf_spdm_Reserved, tvb, offset, 12, ENC_LITTLE_ENDIAN);
    offset += 12;
    ExtAsymCount = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(subtree, hf_spdm_ALG_ExtAsymCount, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    ExtHashCount = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(subtree, hf_spdm_ALG_ExtHashCount, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    if (ExtAsymCount != 0) {
        proto_tree_add_item(subtree, hf_spdm_ALG_ExtAsym, tvb, offset, 4 * ExtAsymCount, ENC_LITTLE_ENDIAN);
        offset += 4 * ExtAsymCount;
    }
    if (ExtHashCount != 0) {
        proto_tree_add_item(subtree, hf_spdm_ALG_ExtHash, tvb, offset, 4 * ExtHashCount, ENC_LITTLE_ENDIAN);
        offset += 4 * ExtHashCount;
    }

    ReqAlgStructLen = tvb_captured_length(tvb) - offset;
    proto_tree_add_item(subtree, hf_spdm_ALG_ReqAlgStruct, tvb, offset, ReqAlgStructLen, ENC_LITTLE_ENDIAN);
}

static void
dissect_algorithms_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{    
    gint    RespAlgStructLen;
    guint8  index;
    guint8  Param1;
    guint8  AlgType;
    guint8  ExtAsymSelCount;
    guint8  ExtHashSelCount;
    guint32 MeasurementHashAlgo;
    guint32 BaseAsymSel;
    guint32 BaseHashSel;
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM ALGORITHMS RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    Param1 = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_ALG_Length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_spdm_ALG_MeasurementSpecificationSel, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Reserved, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    MeasurementHashAlgo = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_spdm_ALG_MeasurementHashAlgo, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    BaseAsymSel = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
    SignatureSize = GetSignatureSize(BaseAsymSel);
    proto_tree_add_item(subtree, hf_spdm_ALG_BaseAsymSel, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    BaseHashSel = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
    HashSize = GetHashSize(BaseHashSel);
    proto_tree_add_item(subtree, hf_spdm_ALG_BaseHashSel, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(subtree, hf_spdm_Reserved, tvb, offset, 12, ENC_LITTLE_ENDIAN);
    offset += 12;
    ExtAsymSelCount = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(subtree, hf_spdm_ALG_ExtAsymSelCount, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    ExtHashSelCount = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(subtree, hf_spdm_ALG_ExtHashSelCount, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    if (ExtAsymSelCount != 0) {
        proto_tree_add_item(subtree, hf_spdm_ALG_ExtAsymSel, tvb, offset, 4 * ExtAsymSelCount, ENC_LITTLE_ENDIAN);
        offset += 4 * ExtAsymSelCount;
    }
    if (ExtHashSelCount != 0) {
        proto_tree_add_item(subtree, hf_spdm_ALG_ExtHashSel, tvb, offset, 4 * ExtHashSelCount, ENC_LITTLE_ENDIAN);
        offset += 4 * ExtHashSelCount;
    }
    RespAlgStructLen = tvb_captured_length(tvb) - offset;
    proto_tree_add_item(subtree, hf_spdm_ALG_RespAlgStruct, tvb, offset, RespAlgStructLen, ENC_LITTLE_ENDIAN);

    for (index = 0; index < Param1; index ++) {
        AlgType = tvb_get_guint8(tvb, offset);
        switch (AlgType) {
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
            DheKeySize = GetSpdmDheKeySize(tvb_get_guint8(tvb, offset + 2));
            break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
            break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
            break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
            break;
        }
        offset += 4;
    }
    
}

static void
dissect_get_digests_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM GET DIGESTS REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_digests_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    guint8 index;
    guint8 Param2;
    guint8 SlotCount;
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM DIGESTS RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    Param2 = tvb_get_guint8(tvb, offset);
    SlotCount = 0;
    for (index = 0; index < 8; index++) {
        if (((1 << index) & Param2) != 0) {
        SlotCount ++;
        }
    }
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    
    for (index = 0; index < SlotCount; index ++) {
        proto_tree_add_item(subtree, hf_spdm_digests_digest, tvb, offset, HashSize, ENC_LITTLE_ENDIAN);
        if ((index + 1) == SlotCount) {
            break;
        }
        offset += HashSize;
    }
}

static void
dissect_get_certificate_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM GET CERTIFICATE REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Cert_Offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_spdm_Cert_Length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

static void
dissect_certificate_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    guint16 PortionLength;
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM CERTIFICATE RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    PortionLength = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_spdm_Cert_PortionLength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_spdm_Cert_RemainderLength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    if (PortionLength != 0) {
        proto_tree_add_item(subtree, hf_spdm_Cert_CertChain, tvb, offset, PortionLength, ENC_LITTLE_ENDIAN);
    } 
}

static void
dissect_get_challenge_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM GET CHANLLENGE REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    ChallengeRequestParam2 = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_challenge_Nonce, tvb, offset, 32, ENC_LITTLE_ENDIAN);
}

static void
dissect_challenge_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    guint16 OpaqueLength;
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM CHANLLENGE_AUTH RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_challenge_CertChainHash, tvb, offset, HashSize, ENC_LITTLE_ENDIAN);
    offset += HashSize;
    proto_tree_add_item(subtree, hf_spdm_challenge_Nonce, tvb, offset, 32, ENC_LITTLE_ENDIAN);
    offset += 32;
    if (ChallengeRequestParam2 != 0) {
        proto_tree_add_item(subtree, hf_spdm_challenge_MeasurementSummaryHash, tvb, offset, HashSize, ENC_LITTLE_ENDIAN);
        offset += HashSize;
    }
    OpaqueLength = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_spdm_challenge_OpaqueLength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    if (OpaqueLength != 0) {
        proto_tree_add_item(subtree, hf_spdm_challenge_OpaqueData, tvb, offset, OpaqueLength, ENC_LITTLE_ENDIAN);
        offset += OpaqueLength;
    }
    proto_tree_add_item(subtree, hf_spdm_challenge_Signature, tvb, offset, SignatureSize, ENC_LITTLE_ENDIAN);
}

static void
dissect_get_mesurements_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM GET MEASUREMENTS REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    MesurementsRequestParam1 = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    if ((MesurementsRequestParam1 & 0x1) != 0) {
        proto_tree_add_item(subtree, hf_spdm_measurements_Nonce, tvb, offset, 32, ENC_LITTLE_ENDIAN);
        offset += 32;
        proto_tree_add_item(subtree, hf_spdm_measurements_SlotIDParam, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    }
}

static void
dissect_mesurements_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    guint32  MeasurementRecordLength;
    guint16 OpaqueLength; 
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM MEASUREMENTS RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_measurements_NumberOfBlocks, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    MeasurementRecordLength = tvb_get_guint24(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_spdm_measurements_MeasurementRecordLength, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;
    if (MeasurementRecordLength != 0) {
        proto_tree_add_item(subtree, hf_spdm_measurements_MeasurementRecord, tvb, offset, MeasurementRecordLength, ENC_LITTLE_ENDIAN);
        offset += MeasurementRecordLength;
    }
    if ((MesurementsRequestParam1 & 0x1) != 0) {
        proto_tree_add_item(subtree, hf_spdm_measurements_Nonce, tvb, offset, 32, ENC_LITTLE_ENDIAN);
        offset += 32;
        OpaqueLength = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(subtree, hf_spdm_measurements_OpaqueLength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(subtree, hf_spdm_measurements_OpaqueData, tvb, offset, OpaqueLength, ENC_LITTLE_ENDIAN);
        offset += OpaqueLength;
        proto_tree_add_item(subtree, hf_spdm_measurements_Signature, tvb, offset, SignatureSize, ENC_LITTLE_ENDIAN);
    }
    
}

static void
dissect_error_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM ERROR RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_ExtendedErrorData, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_respond_if_ready_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM RESPOND IF READY REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_vendor_defined_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    guint8  Len;
    guint16 ReqLength;
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM VENDOR DEFINED REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_vendor_defined_StandardID, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    Len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(subtree, hf_spdm_vendor_defined_Len, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_vendor_defined_VendorID, tvb, offset, Len, ENC_LITTLE_ENDIAN);
    offset += Len;
    ReqLength = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_spdm_vendor_defined_ReqLength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_spdm_vendor_defined_ReqPayload, tvb, offset, ReqLength, ENC_LITTLE_ENDIAN);
}

static void
dissect_vendor_defined_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    guint8  Len;
    guint16 RespLength;
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM VENDOR DEFINED RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_vendor_defined_StandardID, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    Len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(subtree, hf_spdm_vendor_defined_Len, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_vendor_defined_VendorID, tvb, offset, Len, ENC_LITTLE_ENDIAN);
    offset += Len;
    RespLength = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_spdm_vendor_defined_RespLength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_spdm_vendor_defined_RespPayload, tvb, offset, RespLength, ENC_LITTLE_ENDIAN);
}

static void
dissect_key_exchange_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    gint OpaqueDataLength;
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM KEY EXCHANGE REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    KeyExchangeRequestParam1 = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_key_exchange_ReqSessionID, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_spdm_Reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_spdm_key_exchange_RandomData, tvb, offset, 32, ENC_LITTLE_ENDIAN);
    offset += 32;
    proto_tree_add_item(subtree, hf_spdm_key_exchange_ExchangeData, tvb, offset, DheKeySize, ENC_LITTLE_ENDIAN);
    offset += DheKeySize;
    OpaqueDataLength = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_spdm_key_exchange_OpaqueDataLength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_spdm_key_exchange_OpaqueData, tvb, offset, OpaqueDataLength, ENC_LITTLE_ENDIAN);
}

static void
dissect_key_exchange_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    guint16    OpaqueDataLength;
    gboolean   IncludeHmac;
    proto_tree* subtree;

    IncludeHmac = ((CapabilitiesFlags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) == 0);

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM KEY EXCHANGE RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_key_exchange_RspSessionID, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_spdm_key_exchange_MutAuthRequested, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_key_exchange_SlotIDParam, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_key_exchange_RandomData, tvb, offset, 32, ENC_LITTLE_ENDIAN);
    offset += 32;
    proto_tree_add_item(subtree, hf_spdm_key_exchange_ExchangeData, tvb, offset, DheKeySize, ENC_LITTLE_ENDIAN);
    offset += DheKeySize;
    if (KeyExchangeRequestParam1 != 0) {
        proto_tree_add_item(subtree, hf_spdm_key_exchange_MeasurementSummaryHash, tvb, offset, HashSize, ENC_LITTLE_ENDIAN);
        offset += HashSize;
    }
    OpaqueDataLength = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_spdm_key_exchange_OpaqueDataLength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_spdm_key_exchange_OpaqueData, tvb, offset, OpaqueDataLength, ENC_LITTLE_ENDIAN);
    offset += OpaqueDataLength;
    proto_tree_add_item(subtree, hf_spdm_key_exchange_Signature, tvb, offset, SignatureSize, ENC_LITTLE_ENDIAN);
    offset += SignatureSize;
    if (IncludeHmac) {
        proto_tree_add_item(subtree, hf_spdm_key_exchange_ResponderVerifyData, tvb, offset, HashSize, ENC_LITTLE_ENDIAN);
    }
}

static void
dissect_finish_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    guint8   Param1;
    gboolean IncludeSignature;
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM FINISH REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    Param1 = tvb_get_guint8(tvb, offset);
    IncludeSignature = ((Param1 & SPDM_FINISH_REQUEST_ATTRIBUTES_SIGNATURE_INCLUDED) != 0);
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    if (IncludeSignature) {
        proto_tree_add_item(subtree, hf_spdm_finish_Signature, tvb, offset, SignatureSize, ENC_LITTLE_ENDIAN);
        offset += SignatureSize;
    }
    proto_tree_add_item(subtree, hf_spdm_finish_RequesterVerifyData, tvb, offset, HashSize, ENC_LITTLE_ENDIAN);
}

static void
dissect_finish_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    gboolean   IncludeHmac;
    proto_tree* subtree;

    IncludeHmac = ((CapabilitiesFlags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) == 0);

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM FINISH RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    if (IncludeHmac) {
        proto_tree_add_item(subtree, hf_spdm_finish_ResponderVerifyData, tvb, offset, HashSize, ENC_LITTLE_ENDIAN);
    }
}

static void
dissect_psk_exchange_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    guint16 P;
    guint16 R;
    guint16 OpaqueDataLength;
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM PSK EXCHANGE REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    PskExchangeRequestParam1 = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_psk_exchange_ReqSessionID, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    P = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_spdm_psk_exchange_P, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    R = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_spdm_psk_exchange_R, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    OpaqueDataLength = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_spdm_psk_exchange_OpaqueDataLength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_spdm_psk_exchange_PSKHint, tvb, offset, P, ENC_LITTLE_ENDIAN);
    offset += P;
    proto_tree_add_item(subtree, hf_spdm_psk_exchange_RequesterContext, tvb, offset, R, ENC_LITTLE_ENDIAN);
    offset += R;
    proto_tree_add_item(subtree, hf_spdm_psk_exchange_OpaqueData, tvb, offset, OpaqueDataLength, ENC_LITTLE_ENDIAN);
    offset += OpaqueDataLength;
}

static void
dissect_psk_exchange_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    guint16 Q;
    guint16 OpaqueDataLength;
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM PSK EXCHANGE RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_psk_exchange_RepSessionID, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(subtree, hf_spdm_Reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    Q = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_spdm_psk_exchange_Q, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    OpaqueDataLength = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_spdm_psk_exchange_OpaqueDataLength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    if (PskExchangeRequestParam1 != 0) {
        proto_tree_add_item(subtree, hf_spdm_psk_exchange_MeasurementSummaryHash, tvb, offset, HashSize, ENC_LITTLE_ENDIAN);
        offset += HashSize;
    }
    proto_tree_add_item(subtree, hf_spdm_psk_exchange_ResponderContext, tvb, offset, Q, ENC_LITTLE_ENDIAN);
    offset += Q;
    proto_tree_add_item(subtree, hf_spdm_psk_exchange_OpaqueData, tvb, offset, OpaqueDataLength, ENC_LITTLE_ENDIAN);
    offset += OpaqueDataLength;
    proto_tree_add_item(subtree, hf_spdm_psk_exchange_ResponderVerifyData, tvb, offset, HashSize, ENC_LITTLE_ENDIAN);
}

static void
dissect_psk_finish_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM PSK FINISH REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_psk_finish_RequesterVerifyData, tvb, offset, HashSize, ENC_LITTLE_ENDIAN);
}

static void
dissect_psk_finish_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM PSK FINISH RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_heartbeat_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM HEARTBEAT REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_heartbeat_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM HEARTBEAT RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_key_update_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM KEY UPDATE REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_key_update_ack_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM KEY UPDATE ACK RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_get_encapsulated_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM GET ENCAPSULATED REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_encapsulated_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   gint EncapsulatedRequestLen;
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM ENCAPSULATED RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    EncapsulatedRequestLen = tvb_captured_length(tvb) - offset;
    proto_tree_add_item(subtree, hf_spdm_EncapsulatedRequest, tvb, offset, EncapsulatedRequestLen, ENC_LITTLE_ENDIAN);
}

static void
dissect_deliver_encapsulated_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    gint EncapsulatedResponseLen;
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM DELIVER ENCAPSULATED REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    EncapsulatedResponseLen = tvb_captured_length(tvb) - offset;
    proto_tree_add_item(subtree, hf_spdm_EncapsulatedResponse, tvb, offset, EncapsulatedResponseLen, ENC_LITTLE_ENDIAN);
}

static void
dissect_encapsulated_ack_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    gint EncapsulatedRequestLen;
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM ENCAPSULATED ACK RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    EncapsulatedRequestLen = tvb_captured_length(tvb) - offset;
    proto_tree_add_item(subtree, hf_spdm_EncapsulatedRequest, tvb, offset, EncapsulatedRequestLen, ENC_LITTLE_ENDIAN);
}

static void
dissect_end_session_request_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM END SESSION REQUEST MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_end_session_ack_response_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{   
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, spdm_ett.spdm, 0, "SPDM END SESSION ACK RESPONSE MESSAGE");

    proto_tree_add_item(subtree, hf_spdm_SPDMVersion, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_RequestResponseCode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(subtree, hf_spdm_Param2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

static
gboolean
check_message_duplicate_dissect(guint number)
{
    gint index;

    for (index = 0; index < sizeof(RecordMeassageNum); index ++) {
        if (number == RecordMeassageNum[index]) {
            return FALSE;
        }
    }

    return TRUE;
}

/* This method dissects fully reassembled messages */
static int
dissect_spdm_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{  
    gint    offset = 0;
    guint   length;
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

    length = tvb_captured_length(tvb);

    const guchar *cp = tvb_get_ptr(tvb, 0, length);

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
        if (check_message_duplicate_dissect(pinfo->num)) {
            RecordMeassageNum[RecordMessageIndex] = pinfo->num;
            RecordMessageIndex++;
            DumpMctpMessage(cp + 12, (guint32) length);
        }

        proto_tree_add_item(subtree, hf_spdm_MCTPMessageType, tvb, offset, 1, ENC_BIG_ENDIAN);
        guint MCTPMessageType = tvb_get_guint8(tvb, 12);
        offset += 1;
        if (MCTPMessageType == 0x05) {
            RequestResponseCode = tvb_get_guint8(tvb, 14);
            switch(RequestResponseCode) {
                case SPDM_GET_VERSION:
                    dissect_get_version_request_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_VERSION:
                    dissect_version_response_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_GET_CAPABILITIES:
                    dissect_get_capabilities_request_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_CAPABILITIES :
                    dissect_capabilities_response_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_NEGOTIATE_ALGORITHMS:
                    dissect_negotiate_algorithms_request_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_ALGORITHMS:
                    dissect_algorithms_response_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_GET_DIGESTS:
                    dissect_get_digests_request_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_DIGESTS:
                    dissect_digests_response_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_GET_CERTIFICATE:
                    dissect_get_certificate_request_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_CERTIFICATE:
                    dissect_certificate_response_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_CHALLENGE:
                    dissect_get_challenge_request_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_CHALLENGE_AUTH:
                    dissect_challenge_response_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_GET_MEASUREMENTS:
                    dissect_get_mesurements_request_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_MEASUREMENTS:
                    dissect_mesurements_response_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_ERROR:
                    dissect_error_response_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_RESPOND_IF_READY:
                    dissect_respond_if_ready_request_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_VENDOR_DEFINED_REQUEST:
                    dissect_vendor_defined_request_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_VENDOR_DEFINED_RESPONSE:
                    dissect_vendor_defined_response_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_KEY_EXCHANGE:
                    dissect_key_exchange_request_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_KEY_EXCHANGE_RSP:
                    dissect_key_exchange_response_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_FINISH:
                    dissect_finish_request_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_FINISH_RSP:
                    dissect_finish_response_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_PSK_EXCHANGE:
                    dissect_psk_exchange_request_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_PSK_EXCHANGE_RSP:
                    dissect_psk_exchange_response_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_PSK_FINISH:
                    dissect_psk_finish_request_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_PSK_FINISH_RSP:
                    dissect_psk_finish_response_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_HEARTBEAT:
                    dissect_heartbeat_request_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_HEARTBEAT_ACK:
                    dissect_heartbeat_response_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_KEY_UPDATE:
                    dissect_key_update_request_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_KEY_UPDATE_ACK:
                    dissect_key_update_ack_response_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_GET_ENCAPSULATED_REQUEST:
                    dissect_get_encapsulated_request_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_ENCAPSULATED_REQUEST:
                    dissect_encapsulated_response_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_DELIVER_ENCAPSULATED_RESPONSE:
                    dissect_deliver_encapsulated_request_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_ENCAPSULATED_RESPONSE_ACK:
                    dissect_encapsulated_ack_response_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_END_SESSION:
                    dissect_end_session_request_message(tvb, pinfo, subtree, offset);
                    break;
                case SPDM_END_SESSION_ACK:
                    dissect_end_session_ack_response_message(tvb, pinfo, subtree, offset);
                    break;
                default:
                    break;
            }
        }
        else if(MCTPMessageType == 0x06) {
            guint Decoded_MCTPMessageType = tvb_get_guint8(tvb, 23);

            if (Decoded_MCTPMessageType == 0x05) {
                proto_tree_add_item(subtree, hf_spdm_SessionId, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
                proto_tree_add_item(subtree, hf_spdm_SequenceNum, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                proto_tree_add_item(subtree, hf_spdm_SequenceNumSize, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                proto_tree_add_item(subtree, hf_spdm_MessageSize, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                RequestResponseCode = tvb_get_guint8(tvb, 25);
                offset += 1;
                switch(RequestResponseCode) {
                    case SPDM_GET_VERSION:
                        dissect_get_version_request_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_VERSION:
                        dissect_version_response_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_GET_CAPABILITIES:
                        dissect_get_capabilities_request_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_CAPABILITIES :
                        dissect_capabilities_response_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_NEGOTIATE_ALGORITHMS:
                        dissect_negotiate_algorithms_request_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_ALGORITHMS:
                        dissect_algorithms_response_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_GET_DIGESTS:
                        dissect_get_digests_request_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_DIGESTS:
                        dissect_digests_response_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_GET_CERTIFICATE:
                        dissect_get_certificate_request_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_CERTIFICATE:
                        dissect_certificate_response_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_CHALLENGE:
                        dissect_get_challenge_request_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_CHALLENGE_AUTH:
                        dissect_challenge_response_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_GET_MEASUREMENTS:
                        dissect_get_mesurements_request_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_MEASUREMENTS:
                        dissect_mesurements_response_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_ERROR:
                        dissect_error_response_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_RESPOND_IF_READY:
                        dissect_respond_if_ready_request_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_VENDOR_DEFINED_REQUEST:
                        dissect_vendor_defined_request_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_VENDOR_DEFINED_RESPONSE:
                        dissect_vendor_defined_response_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_KEY_EXCHANGE:
                        dissect_key_exchange_request_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_KEY_EXCHANGE_RSP:
                        dissect_key_exchange_response_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_FINISH:
                        dissect_finish_request_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_FINISH_RSP:
                        dissect_finish_response_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_PSK_EXCHANGE:
                        dissect_psk_exchange_request_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_PSK_EXCHANGE_RSP:
                        dissect_psk_exchange_response_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_PSK_FINISH:
                        dissect_psk_finish_request_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_PSK_FINISH_RSP:
                        dissect_psk_finish_response_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_HEARTBEAT:
                        dissect_heartbeat_request_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_HEARTBEAT_ACK:
                        dissect_heartbeat_response_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_KEY_UPDATE:
                        dissect_key_update_request_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_KEY_UPDATE_ACK:
                        dissect_key_update_ack_response_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_GET_ENCAPSULATED_REQUEST:
                        dissect_get_encapsulated_request_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_ENCAPSULATED_REQUEST:
                        dissect_encapsulated_response_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_DELIVER_ENCAPSULATED_RESPONSE:
                        dissect_deliver_encapsulated_request_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_ENCAPSULATED_RESPONSE_ACK:
                        dissect_encapsulated_ack_response_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_END_SESSION:
                        dissect_end_session_request_message(tvb, pinfo, subtree, offset);
                        break;
                    case SPDM_END_SESSION_ACK:
                        dissect_end_session_ack_response_message(tvb, pinfo, subtree, offset);
                        break;
                    default:
                        break;
                }
            }
        }
    }
       
    return tvb_captured_length(tvb);
}

/* determine PDU length of protocol spdm */
static guint32
get_spdm_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return (guint32)tvb_get_ntohl(tvb, offset + 8) + FRAME_HEADER_LEN; 
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
        { &hf_spdm_Reserved,
            { "Reserved", "spdm.Reserved",
            FT_NONE, BASE_NONE,
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
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_ALG_BaseHashAlgo,
            { "BaseHashAlgo", "spdm.BaseHashAlgo",
            FT_UINT32, BASE_HEX,
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
            FT_NONE, BASE_NONE,
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
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_digests_digest,
            { "Digest", "spdm.Digest",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_Cert_Offset,
            { "Offset", "spdm.Offset",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_Cert_Length,
            { "Length", "spdm.Length",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_Cert_PortionLength,
            { "PortionLength", "spdm.PortionLength",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_Cert_RemainderLength,
            { "RemainderLength", "spdm.RemainderLength",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_Cert_CertChain,
            { "CertChain", "spdm.CertChain",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_challenge_Nonce,
            { "Nonce", "spdm.Nonce",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_challenge_CertChainHash,
            { "CertChainHash", "spdm.CertChainHash",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_challenge_MeasurementSummaryHash,
            { "MeasurementSummaryHash", "spdm.MeasurementSummaryHash",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_challenge_OpaqueLength,
            { "OpaqueLength", "spdm.OpaqueLength",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_challenge_OpaqueData,
            { "OpaqueData", "spdm.OpaqueData",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_challenge_Signature,
            { "Signature", "spdm.Signature",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_measurements_Nonce,
            { "Nonce", "spdm.Nonce",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_measurements_SlotIDParam,
            { "SlotIDParam", "spdm.SlotIDParam",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_measurements_NumberOfBlocks,
            { "NumberOfBlocks", "spdm.NumberOfBlocks",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_measurements_MeasurementRecordLength,
            { "MeasurementRecordLength", "spdm.MeasurementRecordLength",
            FT_UINT24, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_measurements_MeasurementRecord,
            { "MeasurementRecord", "spdm.MeasurementRecord",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_measurements_OpaqueLength,
            { "OpaqueLength", "spdm.OpaqueLength",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_measurements_OpaqueData,
            { "OpaqueData", "spdm.OpaqueData",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_measurements_Signature,
            { "Signature", "spdm.Signature",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_ExtendedErrorData,
            { "ExtendedErrorData", "spdm.ExtendedErrorData",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_vendor_defined_StandardID,
            { "StandardID", "spdm.StandardID",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_vendor_defined_Len,
            { "Len", "spdm.Len",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_vendor_defined_VendorID,
            { "VendorID", "spdm.VendorID",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_vendor_defined_ReqLength,
            { "ReqLength", "spdm.ReqLength",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_vendor_defined_ReqPayload,
            { "VendorDefinedReqPayload", "spdm.ReqPayload",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_vendor_defined_RespLength,
            { "RespLength", "spdm.RespLength",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_vendor_defined_RespPayload,
            { "VendorDefinedRespPayload", "spdm.RespPayload",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_key_exchange_ReqSessionID,
            { "ReqSessionID", "spdm.ReqSessionID",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_key_exchange_RandomData,
            { "RandomData", "spdm.RandomData",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_key_exchange_ExchangeData,
            { "ExchangeData", "spdm.ExchangeData",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_key_exchange_OpaqueDataLength,
            { "OpaqueDataLength", "spdm.OpaqueDataLength",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_key_exchange_OpaqueData,
            { "OpaqueData", "spdm.OpaqueData",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_key_exchange_RspSessionID,
            { "RspSessionID", "spdm.RspSessionID",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_key_exchange_MutAuthRequested,
            { "MutAuthRequested", "spdm.MutAuthRequested",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_key_exchange_SlotIDParam,
            { "SlotIDParam", "spdm.SlotIDParam",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_key_exchange_MeasurementSummaryHash,
            { "MeasurementSummaryHash", "spdm.MeasurementSummaryHash",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_key_exchange_Signature,
            { "VendorDefinedRespPayload", "spdm.RespPayload",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_key_exchange_ResponderVerifyData,
            { "ResponderVerifyData", "spdm.ResponderVerifyData",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_finish_Signature,
            { "Signature", "spdm.Signature",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_finish_RequesterVerifyData,
            { "RequesterVerifyData", "spdm.RequesterVerifyData",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_finish_ResponderVerifyData,
            { "ResponderVerifyData", "spdm.ResponderVerifyData",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_psk_exchange_ReqSessionID,
            { "ReqSessionID", "spdm.ReqSessionID",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_psk_exchange_P,
            { "P", "spdm.P",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_psk_exchange_R,
            { "R", "spdm.R",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_psk_exchange_OpaqueDataLength,
            { "OpaqueDataLength", "spdm.OpaqueDataLength",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_psk_exchange_PSKHint,
            { "PSKHint", "spdm.PSKHint",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_psk_exchange_RequesterContext,
            { "RequesterContext", "spdm.RequesterContext",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_psk_exchange_OpaqueData,
            { "OpaqueData", "spdm.OpaqueData",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_psk_exchange_RepSessionID,
            { "RepSessionID", "spdm.RepSessionID",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_psk_exchange_Q,
            { "Q", "spdm.Q",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_psk_exchange_MeasurementSummaryHash,
            { "MeasurementSummaryHash", "spdm.MeasurementSummaryHash",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_psk_exchange_ResponderContext,
            { "ResponderContext", "spdm.ResponderContext",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_psk_exchange_ResponderVerifyData,
            { "ResponderVerifyData", "spdm.ResponderVerifyData",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_psk_finish_RequesterVerifyData,
            { "RequesterVerifyData", "spdm.RequesterVerifyData",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_EncapsulatedRequest,
            { "EncapsulatedRequest", "spdm.EncapsulatedRequest",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_EncapsulatedResponse,
            { "EncapsulatedResponse", "spdm.EncapsulatedResponse",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_SessionId,
            { "SessionId", "spdm.SessionId",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_SequenceNum,
            { "SequenceNum", "spdm.SequenceNum",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_SequenceNumSize,
            { "SequenceNumSize", "spdm.SequenceNumSize",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_spdm_MessageSize,
            { "MessageSize", "spdm.MessageSize",
            FT_UINT16, BASE_HEX,
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

    if (!HexStringToBuffer (PskBuffer, &mPskBuffer, &mPskBufferSize)) {
        exit (0);
        }
    if (!HexStringToBuffer (DheSecretBuffer, &mDheSecretBuffer, &mDheSecretBufferSize)) {
        exit (0);
    }
    InitSpdmDump();
}
