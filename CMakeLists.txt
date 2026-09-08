cmake_minimum_required(VERSION 3.16)
project(multiproto_daemon C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_definitions(-D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE)

option(ENABLE_PN_TESTS "PROFINET 스택 단위/랩 테스트" ON)
option(ENABLE_MB_TESTS "Modbus 스택 단위 테스트" ON)
option(ENABLE_SLMP_TESTS "SLMP 스택/어댑터 단위 테스트" ON)
option(ENABLE_EIP_TESTS "EtherNet/IP 스택 단위 테스트" ON)
option(ENABLE_SENSOR_DEMO "센서 데모 + CODESYS 풀테스트 마스터" ON)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)

# cJSON: 배포판 패키지(libcjson-dev) 우선, 없으면 FetchContent
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
    FetchContent_GetProperties(cjson_src)
    add_library(cjson_local INTERFACE)
    target_link_libraries(cjson_local INTERFACE cjson)
    target_include_directories(cjson_local INTERFACE ${cjson_src_SOURCE_DIR})
    set(CJSON_TARGET cjson_local)
endif()

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
)
target_link_libraries(core PUBLIC ${CJSON_TARGET})

# ---- Modbus TCP 스택 (자체 구현) ----
add_library(mb_stack STATIC stacks/modbus/src/mb_stack.c)
target_include_directories(mb_stack PUBLIC stacks/modbus/include)
target_include_directories(mb_stack PRIVATE include core)

add_library(adapter_modbus STATIC
    adapters/modbus/modbus_adapter.c
    adapters/modbus/modbus_codec.c
)
target_include_directories(adapter_modbus PUBLIC adapters/modbus)
target_include_directories(adapter_modbus PRIVATE include core stacks/modbus/include)
target_link_libraries(adapter_modbus PUBLIC ${CJSON_TARGET} mb_stack m)

# ---- SLMP Binary 3E 스택 (자체 구현) ----
add_library(slmp_stack STATIC stacks/slmp/src/slmp_stack.c)
target_include_directories(slmp_stack PUBLIC stacks/slmp/include)
target_include_directories(slmp_stack PRIVATE include core)
target_link_libraries(slmp_stack PUBLIC Threads::Threads)

add_library(adapter_slmp STATIC
    adapters/slmp/slmp_adapter.c
    adapters/slmp/slmp_codec.c
)
target_include_directories(adapter_slmp PUBLIC adapters/slmp)
target_include_directories(adapter_slmp PRIVATE include core stacks/slmp/include)
target_link_libraries(adapter_slmp PUBLIC ${CJSON_TARGET} slmp_stack m)

# ---- CC-Link (스텁) ----
add_library(adapter_cclink STATIC adapters/cclink/cclink_adapter.c)
target_include_directories(adapter_cclink PUBLIC adapters/cclink)
target_include_directories(adapter_cclink PRIVATE include core)

# ---- EtherNet/IP 스택 (자체 구현) ----
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

add_library(adapter_ethernetip STATIC adapters/ethernetip/ethernetip_adapter.c)
target_include_directories(adapter_ethernetip PUBLIC adapters/ethernetip)
target_include_directories(adapter_ethernetip PRIVATE include core stacks/ethernetip/include)
target_link_libraries(adapter_ethernetip PUBLIC ${CJSON_TARGET} eip_stack)

# ---- PROFINET IO Device 스택 ----
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
    stacks/profinet/src/pn_alarm.c
    stacks/profinet/src/pn_stack.c
)
target_include_directories(pn_stack PUBLIC stacks/profinet/include)
target_include_directories(pn_stack PRIVATE include core)
target_link_libraries(pn_stack PUBLIC Threads::Threads)

add_library(adapter_profinet STATIC adapters/profinet/profinet_adapter.c)
target_include_directories(adapter_profinet PUBLIC adapters/profinet)
target_include_directories(adapter_profinet PRIVATE include core stacks/profinet/include)
target_link_libraries(adapter_profinet PUBLIC ${CJSON_TARGET} pn_stack)

if(ENABLE_PN_TESTS)
    add_executable(test_pn_stack tests/test_pn_stack.c)
    target_include_directories(test_pn_stack PRIVATE stacks/profinet/include include core)
    target_link_libraries(test_pn_stack PRIVATE pn_stack)

    add_executable(pn_device_run tests/pn_device_run.c)
    target_include_directories(pn_device_run PRIVATE stacks/profinet/include include core)
    target_link_libraries(pn_device_run PRIVATE pn_stack)

    add_executable(dcp_probe tests/dcp_probe.c)
    target_include_directories(dcp_probe PRIVATE stacks/profinet/include include core)
    target_link_libraries(dcp_probe PRIVATE pn_stack)

    add_executable(pn_controller_sim tests/pn_controller_sim.c)
    target_include_directories(pn_controller_sim PRIVATE stacks/profinet/include include core)
    target_link_libraries(pn_controller_sim PRIVATE pn_stack)

    add_executable(pn_pi_pretest tests/pn_pi_pretest.c)
    target_include_directories(pn_pi_pretest PRIVATE stacks/profinet/include include core)
    target_link_libraries(pn_pi_pretest PRIVATE pn_stack)

    add_executable(pn_codesys_beta tests/pn_codesys_beta.c)
    target_include_directories(pn_codesys_beta PRIVATE stacks/profinet/include include core)
    target_link_libraries(pn_codesys_beta PRIVATE pn_stack)

    add_executable(test_pn_adapter tests/test_pn_adapter.c)
    target_include_directories(test_pn_adapter PRIVATE include core stacks/profinet/include adapters/profinet)
    target_link_libraries(test_pn_adapter PRIVATE adapter_profinet)
endif()

if(ENABLE_MB_TESTS)
    add_executable(test_mb_stack tests/test_mb_stack.c)
    target_include_directories(test_mb_stack PRIVATE stacks/modbus/include include core)
    target_link_libraries(test_mb_stack PRIVATE mb_stack)

    add_executable(test_mb_adapter tests/test_mb_adapter.c)
    target_include_directories(test_mb_adapter PRIVATE
        stacks/modbus/include include core adapters/modbus)
    target_link_libraries(test_mb_adapter PRIVATE adapter_modbus)

    add_executable(mb_seeded_server tests/mb_seeded_server.c)
    target_include_directories(mb_seeded_server PRIVATE stacks/modbus/include include core)
    target_link_libraries(mb_seeded_server PRIVATE mb_stack)
endif()

if(ENABLE_SLMP_TESTS)
    add_executable(test_slmp_stack tests/test_slmp_stack.c)
    target_include_directories(test_slmp_stack PRIVATE stacks/slmp/include include core)
    target_link_libraries(test_slmp_stack PRIVATE slmp_stack Threads::Threads)

    add_executable(test_slmp_adapter tests/test_slmp_adapter.c)
    target_include_directories(test_slmp_adapter PRIVATE
        stacks/slmp/include include core adapters/slmp)
    target_link_libraries(test_slmp_adapter PRIVATE adapter_slmp m)
endif()

if(ENABLE_EIP_TESTS)
    add_executable(test_eip_stack tests/test_eip_stack.c)
    target_include_directories(test_eip_stack PRIVATE stacks/ethernetip/include include core)
    target_link_libraries(test_eip_stack PRIVATE eip_stack)
endif()

if(ENABLE_SENSOR_DEMO)
    add_executable(sensor_demo demos/sensor/sensor_demo.c)
    target_include_directories(sensor_demo PRIVATE include core)
    target_link_libraries(sensor_demo PRIVATE
        core
        adapter_modbus
        adapter_slmp
        adapter_cclink
        adapter_ethernetip
        adapter_profinet
    )

    add_executable(pool_master tests/codesys/pool_master.c)
    target_include_directories(pool_master PRIVATE
        include core
        stacks/modbus/include
        stacks/ethernetip/include
        stacks/slmp/include)
    target_link_libraries(pool_master PRIVATE mb_stack eip_stack slmp_stack m)
endif()

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
