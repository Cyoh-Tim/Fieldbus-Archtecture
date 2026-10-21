cmake_minimum_required(VERSION 3.16)
# Product snapshot (see VERSION / CHANGELOG.md). Not fb_api ABI.
project(multiproto_daemon VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_definitions(-D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE)
add_compile_options(-fstack-protector-strong)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()
option(ENABLE_SANITIZERS "Address+Undefined sanitizers" OFF)
option(BUILD_FUZZERS "libFuzzer harnesses (clang -fsanitize=fuzzer)" OFF)
option(PN_ENFORCE_SECURITY_CLASS
       "Production: require PROFINET security_class>=1 (lab default OFF)" OFF)
if(ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
elseif(BUILD_FUZZERS)
    # Instrument stack libs for coverage; executables add -fsanitize=fuzzer.
    add_compile_options(-fsanitize=fuzzer-no-link,address,undefined
                        -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
elseif(NOT BUILD_FUZZERS)
    # FORTIFY_SOURCE requires optimization; skip Debug and fuzzer+ASan builds.
    add_compile_options($<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE>
                        $<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=2>)
endif()

option(ENABLE_EIP_TESTS "EtherNet/IP HMAC + residual stack tests" ON)
option(ENABLE_PN_TESTS "PROFINET HMAC 단위 테스트" ON)
option(ENABLE_MB_TESTS "Modbus TCP stack/adapter unit tests" ON)
option(ENABLE_SLMP_TESTS "SLMP Binary 3E stack/adapter unit tests" ON)
option(BUILD_DAEMON "multiproto_daemon + 어댑터 (cJSON 필요, libmodbus 없음)" ON)
option(BUILD_API "Application C API (fb_api) tests, demo, install headers" ON)
option(BUILD_CTT "Controller Test Tool (pn/eip/mb/slmp stacks + YAML 시나리오)" ON)
option(ENABLE_CTT_AF_PACKET "Compile CTT AF_PACKET lab transport (not used by default ctest)" ON)
option(BUILD_PN_LAB_TOOLS "Build dcp_probe / pn_device_run (manual lab; not ctest)" ON)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# ---- PROFINET IO Device 스택 (자체 구현, CC-B / RT Class 1 / Sec Class 1) ----
# 데몬과 CTT가 공유. BUILD_DAEMON=OFF 이면 cJSON/어댑터 없이 스택+ctt 만 빌드.
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
if(PN_ENFORCE_SECURITY_CLASS)
    target_compile_definitions(pn_stack PUBLIC PN_ENFORCE_SECURITY_CLASS=1)
endif()

# ---- Modbus TCP stack (self-hosted; CTT DUT via mb_stack_handle_adu) ----
add_library(mb_stack STATIC stacks/modbus/src/mb_stack.c)
target_include_directories(mb_stack PUBLIC stacks/modbus/include)
target_include_directories(mb_stack PRIVATE include core)

# ---- SLMP Binary 3E stack (self-hosted; CTT DUT via slmp_stack_handle_request) ----
add_library(slmp_stack STATIC stacks/slmp/src/slmp_stack.c)
target_include_directories(slmp_stack PUBLIC stacks/slmp/include)
target_include_directories(slmp_stack PRIVATE include core)
target_link_libraries(slmp_stack PUBLIC Threads::Threads)

# ---- EtherNet/IP Adapter(+Originator) 스택 (자체 구현, 벤더 SDK 불필요) ----
# 데몬과 CTT가 공유. BUILD_DAEMON=OFF 이면 어댑터 없이 eip_stack+ctt.
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
        FetchContent_GetProperties(cjson_src)
        # Do not mutate the upstream cjson target (install export rejects SOURCE_DIR).
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
        core/fb_api.c
    )
    target_include_directories(core PUBLIC include)
    target_include_directories(core PRIVATE
        core
        adapters/modbus
        adapters/slmp
        adapters/cclink
        adapters/ethernetip
        adapters/profinet
    )
    target_link_libraries(core PUBLIC ${CJSON_TARGET} Threads::Threads m)

    # ---- 어댑터: Modbus (자체 스택 stacks/modbus/, libmodbus 없음) ----
    add_library(adapter_modbus STATIC
        adapters/modbus/modbus_adapter.c
        adapters/modbus/modbus_codec.c
    )
    target_include_directories(adapter_modbus PUBLIC adapters/modbus)
    target_include_directories(adapter_modbus PRIVATE include core stacks/modbus/include)
    target_link_libraries(adapter_modbus PUBLIC ${CJSON_TARGET} mb_stack m)

    # ---- 어댑터: SLMP (자체 스택 stacks/slmp/, Binary 3E) ----
    add_library(adapter_slmp STATIC
        adapters/slmp/slmp_adapter.c
        adapters/slmp/slmp_codec.c
    )
    target_include_directories(adapter_slmp PUBLIC adapters/slmp)
    target_include_directories(adapter_slmp PRIVATE include core stacks/slmp/include)
    target_link_libraries(adapter_slmp PUBLIC ${CJSON_TARGET} slmp_stack m)

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

    # ---- 앱이 링크하는 집합 타깃 (프로토콜 헤더 없이 fb_api.h 만 사용) ----
    add_library(fieldbus INTERFACE)
    target_include_directories(fieldbus INTERFACE include)
    target_link_libraries(fieldbus INTERFACE
        core
        adapter_modbus
        adapter_slmp
        adapter_cclink
        adapter_ethernetip
        adapter_profinet
    )

    # ---- 데몬 실행파일 ----
    add_executable(multiproto_daemon core/main.c)
    target_include_directories(multiproto_daemon PRIVATE include)
    target_link_libraries(multiproto_daemon PRIVATE fieldbus)

    if(BUILD_API)
        include(GNUInstallDirs)
        add_executable(fb_api_demo examples/fb_api_demo.c)
        target_link_libraries(fb_api_demo PRIVATE fieldbus)

        add_executable(fake_sensor_app examples/fake_sensor_app.c)
        target_link_libraries(fake_sensor_app PRIVATE fieldbus m)

        add_executable(test_fb_api tests/test_fb_api.c)
        target_link_libraries(test_fb_api PRIVATE fieldbus m)

        add_executable(test_eip_adapter tests/test_eip_adapter.c)
        target_include_directories(test_eip_adapter PRIVATE
            adapters/ethernetip stacks/ethernetip/include include)
        target_link_libraries(test_eip_adapter PRIVATE fieldbus m)

        add_executable(test_pn_scale tests/test_pn_scale.c)
        target_link_libraries(test_pn_scale PRIVATE fieldbus m)

        install(FILES include/fb_api.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    endif()
endif()

if(BUILD_CTT)
    add_executable(ctt
        tools/ctt/main.c
        tools/ctt/runner.c
        tools/ctt/cycle_clock.c
        tools/ctt/yaml_mini.c
        tools/ctt/mock_eth.c
        tools/ctt/transport.c
        tools/ctt/pcap.c
        tools/ctt/plugin_registry.c
        tools/ctt/proto/profinet/pn_plugin.c
        tools/ctt/proto/ethernetip/eip_plugin.c
        tools/ctt/proto/modbus/mb_plugin.c
        tools/ctt/proto/slmp/slmp_plugin.c
    )
    target_include_directories(ctt PRIVATE
        tools/ctt
        stacks/profinet/include
        stacks/ethernetip/include
        stacks/modbus/include
        stacks/slmp/include
        include
        core
    )
    target_link_libraries(ctt PRIVATE pn_stack eip_stack mb_stack slmp_stack)
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
    add_executable(test_pn_rpc tests/test_pn_rpc.c)
    target_include_directories(test_pn_rpc PRIVATE stacks/profinet/include include core)
    target_link_libraries(test_pn_rpc PRIVATE pn_stack)
    add_executable(test_pn_t12_4 tests/test_pn_t12_4.c)
    target_include_directories(test_pn_t12_4 PRIVATE stacks/profinet/include include core)
    target_link_libraries(test_pn_t12_4 PRIVATE pn_stack)
    add_executable(test_pn_t12_7 tests/test_pn_t12_7.c)
    target_include_directories(test_pn_t12_7 PRIVATE stacks/profinet/include include core)
    target_link_libraries(test_pn_t12_7 PRIVATE pn_stack)
    add_executable(test_pn_t4 tests/test_pn_t4.c)
    target_include_directories(test_pn_t4 PRIVATE stacks/profinet/include include core)
    target_link_libraries(test_pn_t4 PRIVATE pn_stack)
    add_executable(test_pn_dcp tests/test_pn_dcp.c)
    target_include_directories(test_pn_dcp PRIVATE stacks/profinet/include include core)
    target_link_libraries(test_pn_dcp PRIVATE pn_stack)
    add_executable(test_pn_t12_8 tests/test_pn_t12_8.c)
    target_include_directories(test_pn_t12_8 PRIVATE stacks/profinet/include include core)
    target_link_libraries(test_pn_t12_8 PRIVATE pn_stack)
    add_executable(test_pn_t5 tests/test_pn_t5.c)
    target_include_directories(test_pn_t5 PRIVATE stacks/profinet/include include core)
    target_link_libraries(test_pn_t5 PRIVATE pn_stack)
endif()

if(ENABLE_EIP_TESTS)
    add_executable(test_eip_crypto tests/test_eip_crypto.c)
    target_include_directories(test_eip_crypto PRIVATE stacks/ethernetip/include include core)
    target_link_libraries(test_eip_crypto PRIVATE eip_stack)
    add_executable(test_eip_stack tests/test_eip_stack.c)
    target_include_directories(test_eip_stack PRIVATE stacks/ethernetip/include include core)
    target_link_libraries(test_eip_stack PRIVATE eip_stack)
    add_executable(test_eip_t11_1 tests/test_eip_t11_1.c)
    target_include_directories(test_eip_t11_1 PRIVATE stacks/ethernetip/include include core)
    target_link_libraries(test_eip_t11_1 PRIVATE eip_stack)
    add_executable(test_eip_t11_3 tests/test_eip_t11_3.c)
    target_include_directories(test_eip_t11_3 PRIVATE stacks/ethernetip/include include core)
    target_link_libraries(test_eip_t11_3 PRIVATE eip_stack)
    add_executable(test_eip_t11_4 tests/test_eip_t11_4.c)
    target_include_directories(test_eip_t11_4 PRIVATE stacks/ethernetip/include include core)
    target_link_libraries(test_eip_t11_4 PRIVATE eip_stack)
    add_executable(test_eip_t11_5 tests/test_eip_t11_5.c)
    target_include_directories(test_eip_t11_5 PRIVATE stacks/ethernetip/include include core)
    target_compile_definitions(test_eip_t11_5 PRIVATE
        "T11_5_EDS_PATH=\"${CMAKE_SOURCE_DIR}/stacks/ethernetip/eds/FieldbusSensor.eds\"")
    target_link_libraries(test_eip_t11_5 PRIVATE eip_stack)
    add_executable(test_eip_t11_6 tests/test_eip_t11_6.c)
    target_include_directories(test_eip_t11_6 PRIVATE stacks/ethernetip/include include core)
    target_link_libraries(test_eip_t11_6 PRIVATE eip_stack)
    add_executable(test_eip_t11_7 tests/test_eip_t11_7.c)
    target_include_directories(test_eip_t11_7 PRIVATE stacks/ethernetip/include include core)
    target_link_libraries(test_eip_t11_7 PRIVATE eip_stack)
    add_executable(test_eip_t5 tests/test_eip_t5.c)
    target_include_directories(test_eip_t5 PRIVATE stacks/ethernetip/include include core)
    target_link_libraries(test_eip_t5 PRIVATE eip_stack)
    add_executable(test_eip_t11_2 tests/test_eip_t11_2.c)
    target_include_directories(test_eip_t11_2 PRIVATE stacks/ethernetip/include include core)
    target_compile_definitions(test_eip_t11_2 PRIVATE
        "T11_2_EDS_PATH=\"${CMAKE_SOURCE_DIR}/stacks/ethernetip/eds/FieldbusSensor.eds\""
        "T11_2_EXAMPLE_CFG=\"${CMAKE_SOURCE_DIR}/config/example.ethernetip.json\"")
    if(BUILD_DAEMON)
        target_compile_definitions(test_eip_t11_2 PRIVATE T11_2_HAVE_ADAPTER=1)
        target_include_directories(test_eip_t11_2 PRIVATE adapters/ethernetip)
        target_link_libraries(test_eip_t11_2 PRIVATE adapter_ethernetip)
    else()
        target_link_libraries(test_eip_t11_2 PRIVATE eip_stack)
    endif()
endif()

if(ENABLE_MB_TESTS)
    add_executable(test_mb_stack tests/test_mb_stack.c)
    target_include_directories(test_mb_stack PRIVATE stacks/modbus/include include core)
    target_link_libraries(test_mb_stack PRIVATE mb_stack)
    add_executable(test_mb_t9_5 tests/test_mb_t9_5.c)
    target_include_directories(test_mb_t9_5 PRIVATE stacks/modbus/include include core)
    target_link_libraries(test_mb_t9_5 PRIVATE mb_stack)
    if(BUILD_DAEMON)
        add_executable(test_mb_adapter tests/test_mb_adapter.c)
        target_include_directories(test_mb_adapter PRIVATE
            stacks/modbus/include include core adapters/modbus)
        target_link_libraries(test_mb_adapter PRIVATE adapter_modbus)

        add_executable(mb_seeded_server tests/mb_seeded_server.c)
        target_include_directories(mb_seeded_server PRIVATE stacks/modbus/include include core)
        target_link_libraries(mb_seeded_server PRIVATE mb_stack)
    endif()
endif()

if(ENABLE_SLMP_TESTS)
    add_executable(test_slmp_stack tests/test_slmp_stack.c)
    target_include_directories(test_slmp_stack PRIVATE stacks/slmp/include include core)
    target_link_libraries(test_slmp_stack PRIVATE slmp_stack Threads::Threads)
    if(BUILD_DAEMON)
        add_executable(test_slmp_adapter tests/test_slmp_adapter.c)
        target_include_directories(test_slmp_adapter PRIVATE
            stacks/slmp/include include core adapters/slmp)
        target_link_libraries(test_slmp_adapter PRIVATE adapter_slmp m)

        add_executable(test_slmp_t10_3 tests/test_slmp_t10_3.c)
        target_include_directories(test_slmp_t10_3 PRIVATE
            stacks/slmp/include include core adapters/slmp)
        target_link_libraries(test_slmp_t10_3 PRIVATE adapter_slmp m)

        add_executable(test_slmp_t10_4 tests/test_slmp_t10_4.c)
        target_include_directories(test_slmp_t10_4 PRIVATE
            stacks/slmp/include include core adapters/slmp)
        target_link_libraries(test_slmp_t10_4 PRIVATE adapter_slmp m)
    endif()
endif()

# ---- Oracle DUTs (tests/oracle) ----
# 스택을 독립 구현체(pymodbus / pymcprotocol / pycomm3 / scapy)로 교차 확인할 때
# 시험 대상(DUT)으로 띄우는 실행 파일. 판정은 Python 오라클이 한다. ctest 대상 아님.
option(BUILD_ORACLE_DUTS "tests/oracle 교차 확인용 DUT 실행 파일" ON)
if(BUILD_ORACLE_DUTS)
    if(NOT TARGET mb_seeded_server)
        add_executable(mb_seeded_server tests/mb_seeded_server.c)
        target_include_directories(mb_seeded_server PRIVATE stacks/modbus/include include core)
        target_link_libraries(mb_seeded_server PRIVATE mb_stack)
    endif()
    add_executable(slmp_oracle_server tests/oracle/dut/slmp_oracle_server.c)
    target_link_libraries(slmp_oracle_server PRIVATE slmp_stack)
    add_executable(slmp_oracle_client tests/oracle/dut/slmp_oracle_client.c)
    target_link_libraries(slmp_oracle_client PRIVATE slmp_stack)
    add_executable(eip_oracle_adapter tests/oracle/dut/eip_oracle_adapter.c)
    target_link_libraries(eip_oracle_adapter PRIVATE eip_stack)
    add_executable(eip_oracle_originator tests/oracle/dut/eip_oracle_originator.c)
    target_link_libraries(eip_oracle_originator PRIVATE eip_stack)
    add_executable(pn_oracle_pipe tests/oracle/dut/pn_oracle_pipe.c)
    target_link_libraries(pn_oracle_pipe PRIVATE pn_stack)
    add_executable(pn_oracle_lab tests/oracle/dut/pn_oracle_lab.c)
    target_link_libraries(pn_oracle_lab PRIVATE pn_stack)
    add_executable(mb_oracle_client tests/oracle/dut/mb_oracle_client.c)
    target_link_libraries(mb_oracle_client PRIVATE mb_stack)
    # 어댑터 수준 DUT (fb_api + adapters/*). 코어·어댑터가 cJSON 을 쓰므로 BUILD_DAEMON=ON 일 때만.
    # CI oracle job 은 BUILD_DAEMON=ON 으로 이 타깃까지 모두 빌드한다.
    if(BUILD_DAEMON)
        add_executable(eip_oracle_fbapi tests/oracle/dut/eip_oracle_fbapi.c)
        target_link_libraries(eip_oracle_fbapi PRIVATE fieldbus)
        add_executable(mb_slmp_oracle_app tests/oracle/dut/mb_slmp_oracle_app.c)
        target_link_libraries(mb_slmp_oracle_app PRIVATE fieldbus m)
        # --wrap=pn_stack_create 로 어댑터가 만든 스택에 mock Ethernet 을 붙인다.
        add_executable(pn_oracle_app tests/oracle/dut/pn_oracle_app.c)
        target_link_libraries(pn_oracle_app PRIVATE fieldbus m)
        target_link_options(pn_oracle_app PRIVATE "LINKER:--wrap=pn_stack_create")
    endif()
endif()

enable_testing()

if(ENABLE_PN_TESTS)
    add_test(NAME test_pn_crypto COMMAND test_pn_crypto)
    add_test(NAME test_pn_rpc COMMAND test_pn_rpc)
    add_test(NAME test_pn_t12_4 COMMAND test_pn_t12_4)
    add_test(NAME test_pn_t12_7 COMMAND test_pn_t12_7)
    add_test(NAME test_pn_t4 COMMAND test_pn_t4)
    add_test(NAME test_pn_dcp COMMAND test_pn_dcp)
    add_test(NAME test_pn_t12_8 COMMAND test_pn_t12_8)
    add_test(NAME test_pn_t5 COMMAND test_pn_t5)
endif()

if(ENABLE_EIP_TESTS)
    add_test(NAME test_eip_crypto COMMAND test_eip_crypto)
    add_test(NAME test_eip_stack COMMAND test_eip_stack)
    add_test(NAME test_eip_t11_1 COMMAND test_eip_t11_1)
    add_test(NAME test_eip_t11_2 COMMAND test_eip_t11_2)
    add_test(NAME test_eip_t11_3 COMMAND test_eip_t11_3)
    add_test(NAME test_eip_t11_4 COMMAND test_eip_t11_4)
    add_test(NAME test_eip_t11_5 COMMAND test_eip_t11_5)
    add_test(NAME test_eip_t11_6 COMMAND test_eip_t11_6)
    add_test(NAME test_eip_t11_7 COMMAND test_eip_t11_7)
    add_test(NAME test_eip_t5 COMMAND test_eip_t5)
endif()

if(ENABLE_MB_TESTS)
    add_test(NAME test_mb_stack COMMAND test_mb_stack)
    add_test(NAME test_mb_t9_5 COMMAND test_mb_t9_5)
    if(BUILD_DAEMON)
        add_test(NAME test_mb_adapter COMMAND test_mb_adapter)
    endif()
endif()

if(ENABLE_SLMP_TESTS)
    add_test(NAME test_slmp_stack COMMAND test_slmp_stack)
    if(BUILD_DAEMON)
        add_test(NAME test_slmp_adapter COMMAND test_slmp_adapter)
        add_test(NAME test_slmp_t10_3 COMMAND test_slmp_t10_3)
        add_test(NAME test_slmp_t10_4 COMMAND test_slmp_t10_4)
    endif()
endif()

if(BUILD_DAEMON AND BUILD_API)
    add_test(NAME test_fb_api COMMAND test_fb_api)
    add_test(NAME test_eip_adapter COMMAND test_eip_adapter)
    set_tests_properties(test_eip_adapter PROPERTIES
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")
    add_test(NAME test_pn_scale COMMAND test_pn_scale)
    # Keep example_fake_sensor_once as Modbus (existing path).
    set(_fake_sensor_tests
        example_fake_sensor_once|example.fake_sensor.json
        example_fake_sensor_once_slmp|example.fake_sensor.slmp.json
        example_fake_sensor_once_ethernetip|example.fake_sensor.ethernetip.json
        example_fake_sensor_once_profinet|example.fake_sensor.profinet.json)
    foreach(_entry ${_fake_sensor_tests})
        string(REPLACE "|" ";" _parts "${_entry}")
        list(GET _parts 0 _tname)
        list(GET _parts 1 _cfg)
        add_test(NAME ${_tname}
            COMMAND fake_sensor_app --once
                    "${CMAKE_SOURCE_DIR}/config/${_cfg}")
        set_tests_properties(${_tname} PROPERTIES
            WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
            LABELS "example")
    endforeach()
    # CODESYS-shaped Modbus TCP master stand-in (not SoftPLC). Shares
    # 127.0.0.1:15560 with example_fake_sensor_once.
    add_test(NAME codesys_shaped_modbus_standin
        COMMAND bash "${CMAKE_SOURCE_DIR}/examples/run_codesys_dut.sh"
                --stand-in --cycles 8 --skip-configure --skip-build
                --build-dir "${CMAKE_BINARY_DIR}")
    set_tests_properties(codesys_shaped_modbus_standin PROPERTIES
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        LABELS "example;codesys"
        TIMEOUT 60
        RESOURCE_LOCK "modbus_15560")
    set_tests_properties(example_fake_sensor_once PROPERTIES
        RESOURCE_LOCK "modbus_15560")
    # In-repo software masters vs live loopback DUT (not CODESYS, not cert).
    add_test(NAME sw_master_soak_short
        COMMAND bash "${CMAKE_SOURCE_DIR}/examples/run_sw_master_soak.sh"
                all --seconds 2 --period-ms 50
                --skip-configure --skip-build
                --build-dir "${CMAKE_BINARY_DIR}")
    set_tests_properties(sw_master_soak_short PROPERTIES
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        LABELS "example;sw_master"
        TIMEOUT 90
        RESOURCE_LOCK "modbus_15560;slmp_15561;eip_15562")
    set_tests_properties(example_fake_sensor_once_slmp PROPERTIES
        RESOURCE_LOCK "slmp_15561")
    set_tests_properties(example_fake_sensor_once_ethernetip PROPERTIES
        RESOURCE_LOCK "eip_15562")
endif()

# Mock scenarios that assert wall-clock bounds (period_max_ms, max_missed,
# jitter_max_ms, max_late) get the "timing" label. CI runs that label with
# ctest --repeat until-pass:3 so scheduler noise on shared runners does not
# fail a job; a real regression still fails all three attempts.
function(fb_label_timing test_name scenario)
    file(READ "${scenario}" _txt)
    if(_txt MATCHES "period_max_ms|max_missed|jitter_max_ms|max_late")
        set_property(TEST ${test_name} APPEND PROPERTY LABELS "timing")
    endif()
endfunction()

if(BUILD_CTT)
    file(GLOB CTT_PN_SCENARIOS CONFIGURE_DEPENDS
         "${CMAKE_SOURCE_DIR}/tests/scenarios/profinet/*.yaml")
    foreach(sc ${CTT_PN_SCENARIOS})
        get_filename_component(sc_name ${sc} NAME_WE)
        add_test(NAME ctt_pn_${sc_name} COMMAND ctt --scenario ${sc})
        set(_pn_labels "profinet")
        # 30s duration soak: optional. Default CI uses -LE soak_ci.
        if(sc_name STREQUAL "soak_ci")
            list(APPEND _pn_labels "soak_ci")
            set_tests_properties(ctt_pn_${sc_name} PROPERTIES TIMEOUT 90)
        endif()
        # Golden replay is mock-only (no NIC). Any YAML with golden: is labeled.
        file(READ "${sc}" _sc_txt)
        if(_sc_txt MATCHES "golden:")
            list(APPEND _pn_labels "golden")
        endif()
        set_tests_properties(ctt_pn_${sc_name} PROPERTIES
            WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
            LABELS "${_pn_labels}")
        fb_label_timing(ctt_pn_${sc_name} ${sc})
    endforeach()
    add_test(NAME ctt_board_data_fresh
        COMMAND python3 "${CMAKE_SOURCE_DIR}/tools/ctt/gen_board_data.py" --check)
    set_tests_properties(ctt_board_data_fresh PROPERTIES
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        LABELS "profinet")
    add_test(NAME ctt_report_schema_v1
        COMMAND python3 "${CMAKE_SOURCE_DIR}/tools/ctt/check_report_schema.py"
                --ctt $<TARGET_FILE:ctt>
                --scenario "${CMAKE_SOURCE_DIR}/tests/scenarios/profinet/rtc1_cyclic_metrics.yaml"
                --protocol profinet)
    set_tests_properties(ctt_report_schema_v1 PROPERTIES
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        LABELS "profinet;timing")  # runs a *_cyclic_metrics scenario
    add_test(NAME ctt_report_schema_eip_v1
        COMMAND python3 "${CMAKE_SOURCE_DIR}/tools/ctt/check_report_schema.py"
                --ctt $<TARGET_FILE:ctt>
                --scenario "${CMAKE_SOURCE_DIR}/tests/scenarios/ethernetip/class1_cyclic_metrics.yaml"
                --protocol ethernetip)
    set_tests_properties(ctt_report_schema_eip_v1 PROPERTIES
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        LABELS "ethernetip;timing")  # runs a *_cyclic_metrics scenario
    add_test(NAME ctt_report_schema_mb_v1
        COMMAND python3 "${CMAKE_SOURCE_DIR}/tools/ctt/check_report_schema.py"
                --ctt $<TARGET_FILE:ctt>
                --scenario "${CMAKE_SOURCE_DIR}/tests/scenarios/modbus/fc03_cyclic_metrics.yaml"
                --protocol modbus_tcp)
    set_tests_properties(ctt_report_schema_mb_v1 PROPERTIES
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        LABELS "modbus;timing")  # runs a *_cyclic_metrics scenario
    add_test(NAME ctt_report_schema_slmp_v1
        COMMAND python3 "${CMAKE_SOURCE_DIR}/tools/ctt/check_report_schema.py"
                --ctt $<TARGET_FILE:ctt>
                --scenario "${CMAKE_SOURCE_DIR}/tests/scenarios/slmp/batch_cyclic_metrics.yaml"
                --protocol slmp)
    set_tests_properties(ctt_report_schema_slmp_v1 PROPERTIES
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        LABELS "slmp;timing")  # runs a *_cyclic_metrics scenario
    file(GLOB CTT_MB_SCENARIOS CONFIGURE_DEPENDS
         "${CMAKE_SOURCE_DIR}/tests/scenarios/modbus/*.yaml")
    foreach(sc ${CTT_MB_SCENARIOS})
        get_filename_component(sc_name ${sc} NAME_WE)
        add_test(NAME ctt_mb_${sc_name} COMMAND ctt --scenario ${sc})
        set_tests_properties(ctt_mb_${sc_name} PROPERTIES
            WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
            LABELS "modbus")
        fb_label_timing(ctt_mb_${sc_name} ${sc})
    endforeach()
    file(GLOB CTT_SLMP_SCENARIOS CONFIGURE_DEPENDS
         "${CMAKE_SOURCE_DIR}/tests/scenarios/slmp/*.yaml")
    foreach(sc ${CTT_SLMP_SCENARIOS})
        get_filename_component(sc_name ${sc} NAME_WE)
        add_test(NAME ctt_slmp_${sc_name} COMMAND ctt --scenario ${sc})
        set_tests_properties(ctt_slmp_${sc_name} PROPERTIES
            WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
            LABELS "slmp")
        fb_label_timing(ctt_slmp_${sc_name} ${sc})
    endforeach()
    file(GLOB CTT_EIP_SCENARIOS CONFIGURE_DEPENDS
         "${CMAKE_SOURCE_DIR}/tests/scenarios/ethernetip/*.yaml")
    foreach(sc ${CTT_EIP_SCENARIOS})
        get_filename_component(sc_name ${sc} NAME_WE)
        add_test(NAME ctt_eip_${sc_name} COMMAND ctt --scenario ${sc})
        set_tests_properties(ctt_eip_${sc_name} PROPERTIES
            WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
            LABELS "ethernetip")
        fb_label_timing(ctt_eip_${sc_name} ${sc})
    endforeach()
    # Lab AF_PACKET is tests/run_ctt_lab.sh — not registered (needs CAP_NET_RAW).
endif()

# One-command product story: fake sensor → fb_api readback → CTT mock
# (Modbus / SLMP / EtherNet/IP / PROFINET). Target exists only when the
# daemon API demo and CTT are both enabled.
if(BUILD_DAEMON AND BUILD_API AND BUILD_CTT)
    add_custom_target(run_mock_flow
        COMMAND "${CMAKE_COMMAND}" -E env "BUILD_DIR=${CMAKE_BINARY_DIR}"
                bash "${CMAKE_SOURCE_DIR}/examples/run_mock_flow.sh"
                --skip-configure
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS fake_sensor_app ctt
        COMMENT "fake sensor → fb_api readback → CTT mock, all protocols (not certification)"
        USES_TERMINAL
    )
endif()

if(BUILD_DAEMON AND BUILD_API)
    add_custom_target(run_codesys_dut
        COMMAND "${CMAKE_COMMAND}" -E env "BUILD_DIR=${CMAKE_BINARY_DIR}"
                bash "${CMAKE_SOURCE_DIR}/examples/run_codesys_dut.sh"
                --skip-configure --stand-in --cycles 8
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS fake_sensor_app
        COMMENT "Modbus DUT + CODESYS-shaped stand-in (not SoftPLC, not certification)"
        USES_TERMINAL
    )
    add_custom_target(run_sw_master_soak
        COMMAND "${CMAKE_COMMAND}" -E env "BUILD_DIR=${CMAKE_BINARY_DIR}"
                bash "${CMAKE_SOURCE_DIR}/examples/run_sw_master_soak.sh"
                --skip-configure all --seconds 3
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        DEPENDS fake_sensor_app
        COMMENT "Software masters vs live loopback DUT (not CODESYS, not certification)"
        USES_TERMINAL
    )
endif()

if(BUILD_FUZZERS)
    function(fb_add_fuzzer name src)
        add_executable(${name} ${src})
        target_include_directories(${name} PRIVATE include core
            stacks/modbus/include stacks/slmp/include
            stacks/ethernetip/include stacks/profinet/include)
        target_link_libraries(${name} PRIVATE ${ARGN} stdc++)
        # libFuzzer is C++; clang does not always search gcc's libstdc++ dir.
        execute_process(COMMAND gcc -print-file-name=libstdc++.so
            OUTPUT_VARIABLE _fb_stdcxx OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET)
        get_filename_component(_fb_stdcxx_dir "${_fb_stdcxx}" DIRECTORY)
        if(_fb_stdcxx_dir)
            target_link_directories(${name} PRIVATE "${_fb_stdcxx_dir}")
        endif()
        target_compile_options(${name} PRIVATE
            -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
        target_link_options(${name} PRIVATE
            -fsanitize=fuzzer,address,undefined)
    endfunction()
    fb_add_fuzzer(fuzz_mb_adu tests/fuzz/fuzz_mb_adu.c mb_stack)
    fb_add_fuzzer(fuzz_slmp_request tests/fuzz/fuzz_slmp_request.c slmp_stack)
    fb_add_fuzzer(fuzz_eip_encap tests/fuzz/fuzz_eip_encap.c eip_stack)
    fb_add_fuzzer(fuzz_eip_io tests/fuzz/fuzz_eip_io.c eip_stack)
    fb_add_fuzzer(fuzz_pn_eth tests/fuzz/fuzz_pn_eth.c pn_stack)
    fb_add_fuzzer(fuzz_pn_rpc tests/fuzz/fuzz_pn_rpc.c pn_stack)
endif()
