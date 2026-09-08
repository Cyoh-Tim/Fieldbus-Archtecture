cmake_minimum_required(VERSION 3.16)
project(multiproto_daemon C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_definitions(-D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE)

option(ENABLE_EIP_TESTS "EtherNet/IP 스택 단위 테스트" ON)
option(ENABLE_PN_TESTS "PROFINET 스택 단위 테스트" ON)

find_package(Threads REQUIRED)

# ---- 의존성 ----
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

# ---- EtherNet/IP Device(+Originator) 스택 (자체 구현, 벤더 SDK 불필요) ----
add_library(eip_stack STATIC
    stacks/ethernetip/src/eip_path_asm.c
    stacks/ethernetip/src/eip_cip.c
    stacks/ethernetip/src/eip_cm.c
    stacks/ethernetip/src/eip_encap.c
    stacks/ethernetip/src/eip_io.c
    stacks/ethernetip/src/eip_client.c
    stacks/ethernetip/src/eip_crypto.c
    stacks/ethernetip/src/eip_sec.c
    stacks/ethernetip/src/eip_stack.c
)
target_include_directories(eip_stack PUBLIC stacks/ethernetip/include)
target_include_directories(eip_stack PRIVATE include core)
find_package(OpenSSL REQUIRED)
target_link_libraries(eip_stack PUBLIC Threads::Threads OpenSSL::SSL OpenSSL::Crypto)

add_library(adapter_ethernetip STATIC adapters/ethernetip/ethernetip_adapter.c)
target_include_directories(adapter_ethernetip PUBLIC adapters/ethernetip)
target_include_directories(adapter_ethernetip PRIVATE include core stacks/ethernetip/include)
target_link_libraries(adapter_ethernetip PUBLIC ${CJSON_TARGET} eip_stack)

if(ENABLE_EIP_TESTS)
    add_executable(test_eip_stack tests/test_eip_stack.c)
    target_include_directories(test_eip_stack PRIVATE stacks/ethernetip/include include core)
    target_link_libraries(test_eip_stack PRIVATE eip_stack)
endif()

# ---- PROFINET IO Device 스택 (자체 구현, CC-B / RT Class 1 / Sec Class 1) ----
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

add_library(adapter_profinet STATIC adapters/profinet/profinet_adapter.c)
target_include_directories(adapter_profinet PUBLIC adapters/profinet)
target_include_directories(adapter_profinet PRIVATE include core stacks/profinet/include)
target_link_libraries(adapter_profinet PUBLIC ${CJSON_TARGET} pn_stack)

if(ENABLE_PN_TESTS)
    add_executable(test_pn_stack tests/test_pn_stack.c)
    target_include_directories(test_pn_stack PRIVATE stacks/profinet/include include core)
    target_link_libraries(test_pn_stack PRIVATE pn_stack)
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
