cmake_minimum_required(VERSION 3.16)
project(multiproto_daemon C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_definitions(-D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE)

option(ENABLE_EIP_TESTS "EtherNet/IP HMAC + residual stack tests" ON)
option(ENABLE_PN_TESTS "PROFINET HMAC 단위 테스트" ON)
option(BUILD_DAEMON "multiproto_daemon + 어댑터 (libmodbus, cJSON 필요)" ON)
option(BUILD_CTT "Controller Test Tool (pn_stack + eip_stack + YAML 시나리오)" ON)
option(ENABLE_CTT_AF_PACKET "Compile CTT AF_PACKET lab transport (not used by default ctest)" ON)
option(BUILD_PN_LAB_TOOLS "Build dcp_probe / pn_device_run (manual lab; not ctest)" ON)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# ---- PROFINET IO Device 스택 (자체 구현, CC-B / RT Class 1 / Sec Class 1) ----
# 데몬과 CTT가 공유. BUILD_DAEMON=OFF 이면 libmodbus 없이 pn_stack+ctt 만 빌드.
add_library(pn_stack STATIC
    stacks/profinet/src/pn_crypto.c
    stacks/profinet/src/pn_eth.c
    stacks/profinet/src/pn_dcp.c
    stacks/profinet/src/pn_lldp.c
    stacks/profinet/src/pn_rt.c
    stacks/profinet/src/pn_rpc.c
    stacks/profinet/src/pn_record.c
    stacks/profinet/src/pn_sec.c
    stacks/profinet/src/pn_snmp.c
    stacks/profinet/src/pn_stack.c
)
target_include_directories(pn_stack PUBLIC stacks/profinet/include)
target_include_directories(pn_stack PRIVATE include core)
target_link_libraries(pn_stack PUBLIC Threads::Threads)

# ---- EtherNet/IP Adapter(+Originator) 스택 (자체 구현, 벤더 SDK 불필요) ----
# 데몬과 CTT가 공유. BUILD_DAEMON=OFF 이면 libmodbus 없이 eip_stack+ctt.
add_library(eip_stack STATIC
    stacks/ethernetip/src/eip_path_asm.c
    stacks/ethernetip/src/eip_cip.c
    stacks/ethernetip/src/eip_cm.c
    stacks/ethernetip/src/eip_encap.c
    stacks/ethernetip/src/eip_io.c
    stacks/ethernetip/src/eip_client.c
    stacks/ethernetip/src/eip_crypto.c
    stacks/ethernetip/src/eip_sec.c
    stacks/ethernetip/src/eip_lldp.c
    stacks/ethernetip/src/eip_stack.c
)
target_include_directories(eip_stack PUBLIC stacks/ethernetip/include)
target_include_directories(eip_stack PRIVATE include core)
target_link_libraries(eip_stack PUBLIC Threads::Threads OpenSSL::SSL OpenSSL::Crypto)

if(BUILD_DAEMON)
    find_package(PkgConfig REQUIRED)

    # cJSON: 코어 config 파싱 + 각 어댑터의 protocol_params/points 파싱에 사용.
    # 배포판 패키지(libcjson-dev)를 pkg-config 로 탐색. 없으면 FetchContent 로 받아온다.
    pkg_check_modules(CJSON QUIET libcjson)
    if(CJSON_FOUND)
        add_library(cjson_iface INTERFACE)
        target_include_directories(cjson_iface INTERFACE ${CJSON_INCLUDE_DIRS})
        target_link_libraries(cjson_iface INTERFACE ${CJSON_LIBRARIES})
        set(CJSON_TARGET cjson_iface)
    else()
        include(FetchContent)
        FetchContent_Declare(
            cjson_src
            GIT_REPOSITORY https://github.com/DaveGamble/cJSON.git
            GIT_TAG v1.7.18
        )
        set(ENABLE_CJSON_TEST OFF CACHE BOOL "" FORCE)
        set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(cjson_src)
        set(CJSON_TARGET cjson)
    endif()

    # libmodbus: pkg-config 로 탐색 (배포판 패키지: libmodbus-dev)
    pkg_check_modules(LIBMODBUS REQUIRED libmodbus)

    # ---- 코어 ----
    add_library(core STATIC
        core/config_loader.c
        core/scheduler.c
        core/adapter_registry.c
    )
    target_include_directories(core PUBLIC
        include
        core
        adapters/modbus
        adapters/slmp
        adapters/cclink
        adapters/ethernetip
        adapters/profinet
        ${LIBMODBUS_INCLUDE_DIRS}
    )
    target_link_libraries(core PUBLIC ${CJSON_TARGET})

    # ---- 어댑터: Modbus (항상 빌드, 벤더 의존성 없음) ----
    add_library(adapter_modbus STATIC adapters/modbus/modbus_adapter.c)
    target_include_directories(adapter_modbus PUBLIC adapters/modbus)
    target_include_directories(adapter_modbus PRIVATE include core ${LIBMODBUS_INCLUDE_DIRS})
    target_link_libraries(adapter_modbus PUBLIC ${CJSON_TARGET} ${LIBMODBUS_LIBRARIES})

    # ---- 어댑터: SLMP (항상 빌드, 벤더 의존성 없음) ----
    add_library(adapter_slmp STATIC adapters/slmp/slmp_adapter.c)
    target_include_directories(adapter_slmp PUBLIC adapters/slmp)
    target_include_directories(adapter_slmp PRIVATE include core)
    target_link_libraries(adapter_slmp PUBLIC ${CJSON_TARGET})

    # ---- 어댑터: CC-Link (스텁, 항상 빌드) ----
    add_library(adapter_cclink STATIC adapters/cclink/cclink_adapter.c)
    target_include_directories(adapter_cclink PUBLIC adapters/cclink)
    target_include_directories(adapter_cclink PRIVATE include core)

    # ---- 어댑터: EtherNet/IP (자체 스택 stacks/ethernetip/) ----
    add_library(adapter_ethernetip STATIC adapters/ethernetip/ethernetip_adapter.c)
    target_include_directories(adapter_ethernetip PUBLIC adapters/ethernetip)
    target_include_directories(adapter_ethernetip PRIVATE include core stacks/ethernetip/include)
    target_link_libraries(adapter_ethernetip PUBLIC ${CJSON_TARGET} eip_stack)

    add_library(adapter_profinet STATIC adapters/profinet/profinet_adapter.c)
    target_include_directories(adapter_profinet PUBLIC adapters/profinet)
    target_include_directories(adapter_profinet PRIVATE include core stacks/profinet/include)
    target_link_libraries(adapter_profinet PUBLIC ${CJSON_TARGET} pn_stack)

    # ---- 데몬 실행파일 ----
    add_executable(multiproto_daemon core/main.c)
    target_include_directories(multiproto_daemon PRIVATE include core)
    target_link_libraries(multiproto_daemon PRIVATE
        core
        adapter_modbus
        adapter_slmp
        adapter_cclink
        adapter_ethernetip
        adapter_profinet
    )
endif()

if(BUILD_CTT)
    add_executable(ctt
        tools/ctt/main.c
        tools/ctt/runner.c
        tools/ctt/yaml_mini.c
        tools/ctt/mock_eth.c
        tools/ctt/transport.c
        tools/ctt/pcap.c
        tools/ctt/plugin_registry.c
        tools/ctt/proto/profinet/pn_plugin.c
        tools/ctt/proto/ethernetip/eip_plugin.c
    )
    target_include_directories(ctt PRIVATE
        tools/ctt
        stacks/profinet/include
        stacks/ethernetip/include
        include
        core
    )
    target_link_libraries(ctt PRIVATE pn_stack eip_stack)
    if(ENABLE_CTT_AF_PACKET)
        target_compile_definitions(ctt PRIVATE CTT_ENABLE_AF_PACKET=1)
    endif()
endif()

if(BUILD_PN_LAB_TOOLS)
    add_executable(dcp_probe tests/dcp_probe.c)
    target_include_directories(dcp_probe PRIVATE stacks/profinet/include)
    add_executable(pn_device_run tests/pn_device_run.c)
    target_include_directories(pn_device_run PRIVATE stacks/profinet/include include core)
    target_link_libraries(pn_device_run PRIVATE pn_stack)
endif()

if(ENABLE_PN_TESTS)
    add_executable(test_pn_crypto tests/test_pn_crypto.c)
    target_include_directories(test_pn_crypto PRIVATE stacks/profinet/include include core)
    target_link_libraries(test_pn_crypto PRIVATE pn_stack)
endif()

if(ENABLE_EIP_TESTS)
    add_executable(test_eip_crypto tests/test_eip_crypto.c)
    target_include_directories(test_eip_crypto PRIVATE stacks/ethernetip/include include core)
    target_link_libraries(test_eip_crypto PRIVATE eip_stack)
    add_executable(test_eip_stack tests/test_eip_stack.c)
    target_include_directories(test_eip_stack PRIVATE stacks/ethernetip/include include core)
    target_link_libraries(test_eip_stack PRIVATE eip_stack)
endif()

enable_testing()

if(ENABLE_PN_TESTS)
    add_test(NAME test_pn_crypto COMMAND test_pn_crypto)
endif()

if(ENABLE_EIP_TESTS)
    add_test(NAME test_eip_crypto COMMAND test_eip_crypto)
    add_test(NAME test_eip_stack COMMAND test_eip_stack)
endif()

if(BUILD_CTT)
    file(GLOB CTT_PN_SCENARIOS CONFIGURE_DEPENDS
         "${CMAKE_SOURCE_DIR}/tests/scenarios/profinet/*.yaml")
    foreach(sc ${CTT_PN_SCENARIOS})
        get_filename_component(sc_name ${sc} NAME_WE)
        add_test(NAME ctt_pn_${sc_name} COMMAND ctt --scenario ${sc})
        set_tests_properties(ctt_pn_${sc_name} PROPERTIES
            WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")
        # 30s duration soak: optional. Default CI uses -LE soak_ci.
        if(sc_name STREQUAL "soak_ci")
            set_tests_properties(ctt_pn_${sc_name} PROPERTIES
                LABELS "soak_ci"
                TIMEOUT 90)
        endif()
        # Golden replay is mock-only (no NIC). Identify / Sec1 Set carry golden:.
        if(sc_name STREQUAL "dcp_identify_name_of_station" OR
           sc_name STREQUAL "dcp_set_sec_class1")
            set_tests_properties(ctt_pn_${sc_name} PROPERTIES LABELS "golden")
        endif()
    endforeach()
    file(GLOB CTT_EIP_SCENARIOS CONFIGURE_DEPENDS
         "${CMAKE_SOURCE_DIR}/tests/scenarios/ethernetip/*.yaml")
    foreach(sc ${CTT_EIP_SCENARIOS})
        get_filename_component(sc_name ${sc} NAME_WE)
        add_test(NAME ctt_eip_${sc_name} COMMAND ctt --scenario ${sc})
        set_tests_properties(ctt_eip_${sc_name} PROPERTIES
            WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
            LABELS "ethernetip")
    endforeach()
    # Lab AF_PACKET is tests/run_ctt_lab.sh — not registered (needs CAP_NET_RAW).
endif()
