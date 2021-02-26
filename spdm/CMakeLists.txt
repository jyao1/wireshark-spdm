# CMakeLists.txt
#
# Wireshark - SPDM plug in
#

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(spdm 0 0 0 1)

set(DISSECTOR_SRC
	packet-spdm.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set_source_files_properties(
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

set(OPENSPDM_LIBRARY
    ${PROJECT_SOURCE_DIR}/openspdm/build/lib/BaseMemoryLib.lib
    ${PROJECT_SOURCE_DIR}/openspdm/build/lib/DebugLibNull.lib
    ${PROJECT_SOURCE_DIR}/openspdm/build/lib/SpdmCommonLib.lib
    ${PROJECT_SOURCE_DIR}/openspdm/build/lib/MbedTlsLib.lib
    ${PROJECT_SOURCE_DIR}/openspdm/build/lib/RngLib.lib
    ${PROJECT_SOURCE_DIR}/openspdm/build/lib/BaseCryptLibMbedTls.lib
    ${PROJECT_SOURCE_DIR}/openspdm/build/lib/MemoryAllocationLib.lib
    ${PROJECT_SOURCE_DIR}/openspdm/build/lib/SpdmCryptLib.lib
    ${PROJECT_SOURCE_DIR}/openspdm/build/lib/SpdmSecuredMessageLib.lib
    ${PROJECT_SOURCE_DIR}/openspdm/build/lib/SpdmTransportMctpLib.lib
    ${PROJECT_SOURCE_DIR}/openspdm/build/lib/SpdmTransportPciDoeLib.lib
    ${PROJECT_SOURCE_DIR}/openspdm/build/lib/SpdmDeviceSecretLibNull.lib
    ${PROJECT_SOURCE_DIR}/openspdm/build/lib/SpdmDumpLib.lib
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}
                    ${PROJECT_SOURCE_DIR}/openspdm/Tool/SpdmDump
                    ${PROJECT_SOURCE_DIR}/openspdm/Include
                    ${PROJECT_SOURCE_DIR}/openspdm/Include/Hal
                    ${PROJECT_SOURCE_DIR}/openspdm/Include/Hal/X64
                    ${PROJECT_SOURCE_DIR}/openspdm/OsStub/Include
)

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

add_plugin_library(spdm epan)

target_link_libraries(spdm epan ${OPENSPDM_LIBRARY})

install_plugin(spdm epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
	  spdm
	SWITCHES
	  -g abort -g termoutput
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_HEADERS}
)

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
