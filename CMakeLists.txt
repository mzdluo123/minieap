cmake_minimum_required(VERSION 3.20)
project(minieap C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(ENABLE_DEBUG "Enable debug logging (-DDEBUG)" OFF)

if(WIN32)
    set(_default_iconv OFF)
    set(_default_gbconv ON)
else()
    set(_default_iconv ON)
    set(_default_gbconv OFF)
endif()
option(ENABLE_ICONV "Use iconv for GBK conversion" ${_default_iconv})
option(ENABLE_GBCONV "Use bundled GBK conversion" ${_default_gbconv})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    option(ENABLE_IF_IMPL_SOCKRAW "Build sockraw if_impl" ON)
else()
    option(ENABLE_IF_IMPL_SOCKRAW "Build sockraw if_impl" OFF)
endif()

if(APPLE OR CMAKE_SYSTEM_NAME MATCHES "BSD")
    option(ENABLE_IF_IMPL_BPF "Build BPF if_impl" ON)
else()
    option(ENABLE_IF_IMPL_BPF "Build BPF if_impl" OFF)
endif()

if(WIN32 OR NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    option(ENABLE_IF_IMPL_LIBPCAP "Build libpcap/Npcap if_impl" ON)
else()
    option(ENABLE_IF_IMPL_LIBPCAP "Build libpcap/Npcap if_impl" OFF)
endif()
if(WIN32)
    set(ENABLE_IF_IMPL_LIBPCAP ON CACHE BOOL "Build libpcap/Npcap if_impl" FORCE)
endif()

option(ENABLE_PACKET_PLUGIN_RJV3 "Build rjv3 packet plugin" ON)
option(ENABLE_PACKET_PLUGIN_PRINTER "Build printer packet plugin" ON)

set(NPCAP_SDK_DIR "" CACHE PATH "Npcap SDK root containing Include/pcap.h")

set(MINIEAP_SOURCES
    minieap.c
    config.c
    packet_builder.c
    md5.c
    eap_state_machine.c
    if_impl/if_impl.c
    packet_plugin/packet_plugin.c
    util/conf_parser.c
    util/linkedlist.c
    util/logging.c
    util/misc.c
    util/net_util.c
    util/packet_util.c
    util/pid_lock.c
    util/sched_alarm.c
)

add_executable(minieap ${MINIEAP_SOURCES})

target_include_directories(minieap PRIVATE
    include
    packet_plugin/rjv3
    packet_plugin/rjv3/rjv3_hashes
)

if(ENABLE_DEBUG)
    target_compile_definitions(minieap PRIVATE DEBUG)
endif()

if(UNIX)
    target_compile_definitions(minieap PRIVATE _GNU_SOURCE)
endif()

if(MSVC)
    target_compile_options(minieap PRIVATE /utf-8)
    target_compile_definitions(minieap PRIVATE
        _CRT_SECURE_NO_WARNINGS
        _WINSOCK_DEPRECATED_NO_WARNINGS
        _CRT_NONSTDC_NO_DEPRECATE
    )
    target_sources(minieap PRIVATE compat/getopt.c)
    target_include_directories(minieap PRIVATE compat)
elseif(MINGW)
    target_compile_options(minieap PRIVATE
        -finput-charset=UTF-8
        -fexec-charset=UTF-8
    )
endif()

if(ENABLE_GBCONV)
    target_sources(minieap PRIVATE util/gbconv.c)
    target_compile_definitions(minieap PRIVATE ENABLE_GBCONV)
endif()

if(ENABLE_ICONV)
    target_compile_definitions(minieap PRIVATE ENABLE_ICONV)
    find_library(ICONV_LIBRARY NAMES iconv libiconv)
    if(ICONV_LIBRARY)
        target_link_libraries(minieap PRIVATE ${ICONV_LIBRARY})
    endif()
endif()

if(ENABLE_IF_IMPL_SOCKRAW)
    target_sources(minieap PRIVATE if_impl/sockraw/if_impl_sockraw.c)
    target_compile_definitions(minieap PRIVATE HAS_IF_IMPL_SOCKRAW)
endif()

if(ENABLE_IF_IMPL_BPF)
    target_sources(minieap PRIVATE if_impl/bpf/if_impl_bpf.c)
    target_compile_definitions(minieap PRIVATE HAS_IF_IMPL_BPF)
endif()

if(ENABLE_IF_IMPL_LIBPCAP)
    target_sources(minieap PRIVATE if_impl/libpcap/if_impl_libpcap.c)
    target_compile_definitions(minieap PRIVATE HAS_IF_IMPL_LIBPCAP)

    if(WIN32)
        set(_npcap_root "")
        if(NPCAP_SDK_DIR AND EXISTS "${NPCAP_SDK_DIR}/Include/pcap.h")
            set(_npcap_root "${NPCAP_SDK_DIR}")
        elseif(EXISTS "${CMAKE_SOURCE_DIR}/third_party/npcap-sdk/Include/pcap.h")
            set(_npcap_root "${CMAKE_SOURCE_DIR}/third_party/npcap-sdk")
        else()
            set(_npcap_zip "${CMAKE_BINARY_DIR}/npcap-sdk-1.16.zip")
            set(_npcap_extract "${CMAKE_BINARY_DIR}/npcap-sdk-extract")
            set(_npcap_url "https://npcap.com/dist/npcap-sdk-1.16.zip")
            message(STATUS "Downloading Npcap SDK from ${_npcap_url}")
            file(DOWNLOAD
                "${_npcap_url}"
                "${_npcap_zip}"
                SHOW_PROGRESS
                TLS_VERIFY ON
                STATUS _npcap_dl_status
            )
            list(GET _npcap_dl_status 0 _npcap_dl_code)
            if(NOT _npcap_dl_code EQUAL 0)
                list(GET _npcap_dl_status 1 _npcap_dl_msg)
                message(FATAL_ERROR
                    "Failed to download Npcap SDK from ${_npcap_url} (${_npcap_dl_msg}). "
                    "Set -DNPCAP_SDK_DIR= to a extracted SDK (Include/pcap.h).")
            endif()
            file(ARCHIVE_EXTRACT INPUT "${_npcap_zip}" DESTINATION "${_npcap_extract}")
            if(EXISTS "${_npcap_extract}/Include/pcap.h")
                set(_npcap_root "${_npcap_extract}")
            else()
                file(GLOB _npcap_pcap_hits "${_npcap_extract}/*/Include/pcap.h")
                if(_npcap_pcap_hits)
                    list(GET _npcap_pcap_hits 0 _npcap_pcap_h)
                    get_filename_component(_npcap_inc "${_npcap_pcap_h}" DIRECTORY)
                    get_filename_component(_npcap_root "${_npcap_inc}" DIRECTORY)
                endif()
            endif()
            if(NOT _npcap_root OR NOT EXISTS "${_npcap_root}/Include/pcap.h")
                message(FATAL_ERROR
                    "Npcap SDK extract did not contain Include/pcap.h. "
                    "Set -DNPCAP_SDK_DIR= to the SDK root. URL: ${_npcap_url}")
            endif()
        endif()

        if(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64")
            set(_npcap_lib_dir "${_npcap_root}/Lib/ARM64")
        elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(_npcap_lib_dir "${_npcap_root}/Lib/x64")
        else()
            set(_npcap_lib_dir "${_npcap_root}/Lib")
        endif()

        target_include_directories(minieap PRIVATE "${_npcap_root}/Include")
        target_link_directories(minieap PRIVATE "${_npcap_lib_dir}")
        target_link_libraries(minieap PRIVATE wpcap Packet)
        target_compile_definitions(minieap PRIVATE WPCAP)
    else()
        find_path(PCAP_INCLUDE_DIR pcap.h)
        find_library(PCAP_LIBRARY pcap)
        if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
            message(FATAL_ERROR "libpcap not found (pcap.h / libpcap).")
        endif()
        target_include_directories(minieap PRIVATE "${PCAP_INCLUDE_DIR}")
        target_link_libraries(minieap PRIVATE "${PCAP_LIBRARY}")
    endif()
endif()

if(ENABLE_PACKET_PLUGIN_RJV3)
    file(GLOB _rjv3_sources CONFIGURE_DEPENDS
        packet_plugin/rjv3/*.c
        packet_plugin/rjv3/rjv3_hashes/*.c
    )
    target_sources(minieap PRIVATE ${_rjv3_sources})
    target_compile_definitions(minieap PRIVATE HAS_PACKET_PLUGIN_RJV3)
endif()

if(ENABLE_PACKET_PLUGIN_PRINTER)
    target_sources(minieap PRIVATE packet_plugin/printer/packet_plugin_printer.c)
    target_compile_definitions(minieap PRIVATE HAS_PACKET_PLUGIN_PRINTER)
endif()

if(WIN32)
    target_sources(minieap PRIVATE util/win32.c)
    target_link_libraries(minieap PRIVATE ws2_32 iphlpapi powrprof)
endif()

option(MINIEAP_BUILD_TESTS "Build Windows recovery regression checks" OFF)
if(MINIEAP_BUILD_TESTS)
    if(NOT WIN32 OR NOT ENABLE_PACKET_PLUGIN_RJV3)
        message(FATAL_ERROR "Recovery checks require Windows and ENABLE_PACKET_PLUGIN_RJV3=ON")
    endif()
    enable_testing()
    get_target_property(_test_sources minieap SOURCES)
    # These units are included by the test with OS/adapter fault injection.
    list(REMOVE_ITEM _test_sources
        minieap.c eap_state_machine.c util/win32.c util/sched_alarm.c
        if_impl/libpcap/if_impl_libpcap.c
        "${CMAKE_CURRENT_SOURCE_DIR}/packet_plugin/rjv3/packet_plugin_rjv3_keepalive.c")
    add_executable(windows_recovery tests/windows_recovery.c ${_test_sources})
    foreach(_property INCLUDE_DIRECTORIES COMPILE_DEFINITIONS COMPILE_OPTIONS LINK_DIRECTORIES LINK_LIBRARIES)
        get_target_property(_value minieap ${_property})
        if(_value)
            set_property(TARGET windows_recovery PROPERTY ${_property} "${_value}")
        endif()
    endforeach()
    add_test(NAME windows_recovery COMMAND windows_recovery)
    set_tests_properties(windows_recovery PROPERTIES TIMEOUT 30)
endif()

if(WIN32)
    install(TARGETS minieap RUNTIME DESTINATION bin)
    install(FILES minieap.conf DESTINATION etc)
else()
    install(TARGETS minieap RUNTIME DESTINATION sbin)
    install(FILES minieap.conf DESTINATION /etc)
endif()
