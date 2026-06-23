cmake_minimum_required(VERSION 3.10)
project(protocol_scanner LANGUAGES CXX VERSION 1.0.0)

# =====================
# 构建配置
# =====================
# 允许 InfoRelease 作为有效的构建类型
set(CMAKE_CONFIGURATION_TYPES "Debug;Release;InfoRelease" CACHE STRING "" FORCE)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build: Debug/Release/InfoRelease" FORCE)
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# C++ 标准
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Debug/Release 模式编译器优化
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -DDEBUG -fno-omit-frame-pointer" CACHE STRING "Flags used by C++ compiler during DEBUG builds" FORCE)

# Release 版本默认优化（不使用 LTO 以减少编译时间和警告）
if(UNIX AND NOT APPLE)
    # Linux 特定优化：-fno-plt 加速 PIC 代码、-mtune 针对通用 CPU、-pipe 使用管道而非文件
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -mtune=generic -fno-plt -pipe" CACHE STRING "Flags used by C++ compiler during RELEASE builds" FORCE)
    # InfoRelease: Release优化 + 保留INFO日志（生产环境)
    set(CMAKE_CXX_FLAGS_INFORELEASE "-O3 -DNDEBUG -DENABLE_LOGGING_INFO -mtune=generic -fno-plt -pipe" CACHE STRING "Flags used by C++ compiler during INFORELEASE builds" FORCE)
else()
    # macOS 和其他系统
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -march=native" CACHE STRING "Flags used by C++ compiler during RELEASE builds" FORCE)
    # InfoRelease: Release优化 + 保留INFO日志（生产环境)
    set(CMAKE_CXX_FLAGS_INFORELEASE "-O3 -DNDEBUG -DENABLE_LOGGING_INFO -march=native" CACHE STRING "Flags used by C++ compiler during INFORELEASE builds" FORCE)
endif()

# 全局编译选项
add_compile_options(-Wall -Wextra -Wno-unused-parameter)
# 禁用 clang pragma 警告（GCC 会忽略未知的 pragma，但不会警告）
add_compile_options($<$<CXX_COMPILER_ID:GNU>:-Wno-unknown-pragmas>)

# 在 Clang/GCC 下开启彩色诊断
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    add_compile_options(-fdiagnostics-color=auto)
endif()

# 性能优化开关（禁用 LTO，减少编译警告和时间）
option(ENABLE_PERFORMANCE_MODE "Enable performance optimizations" ON)
if(ENABLE_PERFORMANCE_MODE)
    add_definitions(-DENABLE_INLINE_PROTOCOLS)
endif()

# macOS 常见包管理前缀，便于 find_package 找到 Homebrew 安装
if(APPLE)
    list(APPEND CMAKE_PREFIX_PATH /opt/homebrew /usr/local)
    # CMake >=4.0 移除了 FindBoost 模块，需要 CONFIG 模式
    # Boost 1.70+ 自带 BoostConfig.cmake, Homebrew 装在 Cellar 下
    if(EXISTS /opt/homebrew/Cellar/boost)
        # 取最新版本 Cellar 目录
        file(GLOB _boost_cellar_dirs /opt/homebrew/Cellar/boost/*)
        list(SORT _boost_cellar_dirs)
        list(REVERSE _boost_cellar_dirs)
        if(_boost_cellar_dirs)
            list(GET _boost_cellar_dirs 0 _boost_cellar_dir)
            get_filename_component(_boost_version "${_boost_cellar_dir}" NAME)
            set(Boost_DIR "${_boost_cellar_dir}/lib/cmake/Boost-${_boost_version}")
            message(STATUS "Detected Boost CMake config at ${Boost_DIR}")
        endif()
    endif()
endif()

# 可选：禁用日志
option(ENABLE_LOGGING "Enable logging via spdlog" ON)

# =====================
# 依赖查找
# =====================
set(_mac_hint "macOS: brew install boost c-ares fmt nlohmann-json spdlog")
set(_deb_hint "Debian/Ubuntu: sudo apt-get install libboost-all-dev libc-ares-dev libfmt-dev nlohmann-json3-dev libspdlog-dev")

find_package(PkgConfig QUIET)

# Boost
# CMake >=4.0 需要 CONFIG 模式；<4.0 用 MODULE 模式回退
find_package(Boost CONFIG COMPONENTS system program_options filesystem QUIET)
if(NOT Boost_FOUND)
    # 低版本 CMake 回退到 MODULE 模式（FindBoost.cmake）
    find_package(Boost COMPONENTS system program_options filesystem QUIET)
endif()
if(NOT Boost_FOUND)
    set(_boost_help "Boost not found. ${_mac_hint}; ${_deb_hint}")
    message(FATAL_ERROR "${_boost_help}")
endif()

# 线程库
find_package(Threads REQUIRED)

# nlohmann/json (优先系统库，其次 FetchContent)
option(ENABLE_BUNDLED_JSON "Download nlohmann_json if system package missing" ON)
unset(JSON_TARGET)
find_package(nlohmann_json 3.11 QUIET)
if(nlohmann_json_FOUND)
    set(JSON_TARGET nlohmann_json::nlohmann_json)
else()
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(NLOHMANN_JSON QUIET IMPORTED_TARGET nlohmann_json)
        if(NLOHMANN_JSON_FOUND)
            add_library(nlohmann_json_pkg INTERFACE)
            target_include_directories(nlohmann_json_pkg INTERFACE ${NLOHMANN_JSON_INCLUDE_DIRS})
            set(JSON_TARGET nlohmann_json_pkg)
        endif()
    endif()
    if(NOT JSON_TARGET AND ENABLE_BUNDLED_JSON)
        message(STATUS "nlohmann_json not found; fetching v3.11.2")
        include(FetchContent)
        FetchContent_Declare(json
            URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz
        )
        FetchContent_MakeAvailable(json)
        set(JSON_TARGET nlohmann_json::nlohmann_json)
    endif()
endif()

# c-ares DNS (optional)
option(USE_CARES "Use c-ares for asynchronous DNS resolution" ON)
set(CARES_TARGET "")
if(USE_CARES)
    find_package(c-ares CONFIG QUIET)
    if(TARGET c-ares::cares)
        set(CARES_TARGET c-ares::cares)
    endif()
    if(NOT CARES_TARGET AND PKG_CONFIG_FOUND)
        pkg_check_modules(CARES QUIET IMPORTED_TARGET libcares)
        if(CARES_FOUND)
            set(CARES_TARGET PkgConfig::CARES)
        endif()
    endif()
    if(NOT CARES_TARGET)
        find_library(CARES_LIBRARY NAMES cares libcares
            PATHS /opt/homebrew/opt/c-ares/lib /usr/local/opt/c-ares/lib
        )
        find_path(CARES_INCLUDE_DIR ares.h
            PATHS /opt/homebrew/opt/c-ares/include /usr/local/opt/c-ares/include
        )
        if(CARES_LIBRARY)
            add_library(cares_fallback INTERFACE)
            target_link_libraries(cares_fallback INTERFACE ${CARES_LIBRARY})
            if(CARES_INCLUDE_DIR)
                target_include_directories(cares_fallback INTERFACE ${CARES_INCLUDE_DIR})
            endif()
            set(CARES_TARGET cares_fallback)
        endif()
    endif()
    if(NOT CARES_TARGET)
        message(WARNING "c-ares not found, building without DNS resolution support. "
            "Install c-ares for DNS features: ${_mac_hint}; ${_deb_hint}")
        set(USE_CARES OFF)
    endif()
endif()
if(NOT USE_CARES)
    message(STATUS "Building without c-ares (CAresResolver disabled, fallback to dig)")
    add_compile_definitions(SCANNER_NO_CARES)
endif()

# =====================
# 源文件与包含目录
# =====================
set(SCANNER_MAIN_SRC
    ${CMAKE_SOURCE_DIR}/src/scanner/main.cpp
)

set(SCANNER_CORE_SRCS
    ${CMAKE_SOURCE_DIR}/src/scanner/dns/dns_resolver.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/dns/dig_resolver.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/common/thread_pool.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/common/io_thread_pool.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/core/session.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/core/crash_inspector.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/core/progress_manager.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/core/utils.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/core/scanner.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/core/mcp_mode.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/vendor/vendor_detector.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/output/result_handler.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/distributed/distributed_queue.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/distributed/progress_store.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/distributed/orchestrator.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/distributed/task_codec.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/distributed/kafka_transport.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/distributed/ingestor.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/deep_probe/openssh_probes.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/deep_probe/vsftpd_telnetd_probes.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/deep_probe/deep_probe_registry.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/deep_probe/deep_probe_impls.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/metrics/metrics_server.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/core/resource_guard.cpp
    # ${CMAKE_SOURCE_DIR}/src/scanner/port_scanner.cpp
)

# c-ares resolver (only when available)
if(USE_CARES)
    list(APPEND SCANNER_CORE_SRCS ${CMAKE_SOURCE_DIR}/src/scanner/dns/cares_resolver.cpp)
endif()

set(PROTOCOL_SRCS
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/smtp_protocol.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/pop3_protocol.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/imap_protocol.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/http_protocol.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/ftp_protocol.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/telnet_protocol.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/ssh_protocol.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/redis_protocol.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/rtsp_protocol.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/sip_protocol.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/mysql_protocol.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/postgresql_protocol.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/mongodb_protocol.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/protocol_factory.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/protocol_registry_init.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/protocol_parsers.cpp
)

set(ALL_CORE_SRCS ${SCANNER_CORE_SRCS} ${PROTOCOL_SRCS})

add_library(scanner_core STATIC ${ALL_CORE_SRCS})
add_executable(scanner ${SCANNER_MAIN_SRC})
add_executable(scanner_distributed ${CMAKE_SOURCE_DIR}/src/scanner/distributed_main.cpp)
add_executable(scanner_ingest ${CMAKE_SOURCE_DIR}/src/scanner/distributed_ingest_main.cpp)
add_executable(scanner_mcp ${CMAKE_SOURCE_DIR}/src/scanner/mcp_main.cpp)

# 项目内头文件
target_include_directories(scanner_core PUBLIC
    ${CMAKE_SOURCE_DIR}/include

)

target_include_directories(scanner PRIVATE
    ${CMAKE_SOURCE_DIR}/include

)

target_include_directories(scanner_distributed PRIVATE
    ${CMAKE_SOURCE_DIR}/include

)

target_include_directories(scanner_ingest PRIVATE
    ${CMAKE_SOURCE_DIR}/include

)

target_include_directories(scanner_mcp PRIVATE
    ${CMAKE_SOURCE_DIR}/include

)

# =====================
# 链接库
# =====================
if(TARGET Boost::system AND TARGET Boost::program_options)
    target_link_libraries(scanner_core PUBLIC Boost::system Boost::program_options Boost::filesystem)
else()
    target_link_libraries(scanner_core PUBLIC ${Boost_LIBRARIES})
endif()

target_link_libraries(scanner_core PUBLIC Threads::Threads)

# fmt (spdlog 依赖)
find_package(fmt CONFIG QUIET)
if(TARGET fmt::fmt)
    target_link_libraries(scanner_core PUBLIC fmt::fmt)
endif()

# nlohmann/json
if(JSON_TARGET)
    target_link_libraries(scanner_core PUBLIC ${JSON_TARGET})
endif()

# libssh2 (optional, for SSH deep probes)
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(LIBSSH2 QUIET IMPORTED_TARGET libssh2)
    if(LIBSSH2_FOUND)
        target_link_libraries(scanner_core PUBLIC PkgConfig::LIBSSH2)
        target_compile_definitions(scanner_core PUBLIC SCANNER_ENABLE_DEEP_PROBE=1)
    else()
        target_compile_definitions(scanner_core PUBLIC SCANNER_ENABLE_DEEP_PROBE=0)
    endif()
else()
    target_compile_definitions(scanner_core PUBLIC SCANNER_ENABLE_DEEP_PROBE=0)
endif()

# librdkafka (optional)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(RDKAFKA QUIET IMPORTED_TARGET rdkafka)
    if(RDKAFKA_FOUND)
        target_link_libraries(scanner_core PUBLIC PkgConfig::RDKAFKA)
        target_compile_definitions(scanner_core PUBLIC SCANNER_ENABLE_KAFKA=1)
    else()
        target_compile_definitions(scanner_core PUBLIC SCANNER_ENABLE_KAFKA=0)
    endif()
else()
    target_compile_definitions(scanner_core PUBLIC SCANNER_ENABLE_KAFKA=0)
endif()

if(NOT ENABLE_LOGGING)
    target_compile_definitions(scanner_core PUBLIC SCANNER_DISABLE_LOGGING)
endif()

# c-ares linking (only if available)
if(CARES_TARGET)
    target_link_libraries(scanner_core PUBLIC ${CARES_TARGET})
endif()

target_link_libraries(scanner PRIVATE scanner_core)
target_link_libraries(scanner_distributed PRIVATE scanner_core)
target_link_libraries(scanner_ingest PRIVATE scanner_core)
target_link_libraries(scanner_mcp PRIVATE scanner_core)

# 要求特性
target_compile_features(scanner_core PUBLIC cxx_std_20)
target_compile_features(scanner PRIVATE cxx_std_20)
target_compile_features(scanner_distributed PRIVATE cxx_std_20)
target_compile_features(scanner_ingest PRIVATE cxx_std_20)
target_compile_features(scanner_mcp PRIVATE cxx_std_20)

# =====================
# 安装规则
# =====================
install(TARGETS scanner scanner_distributed scanner_ingest scanner_mcp RUNTIME DESTINATION bin)
install(DIRECTORY config/ DESTINATION share/protocol-scanner/config)

# =====================
# 快速构建脚本
# =====================
configure_file(
    ${CMAKE_SOURCE_DIR}/build.sh.in
    ${CMAKE_BINARY_DIR}/build.sh
    @ONLY
)

# =====================
# 单元测试
# =====================

option(ENABLE_TESTS "Build unit tests (requires Catch2)" ON)

if(ENABLE_TESTS)
    find_package(Catch2 QUIET)
    if(Catch2_FOUND)
        add_executable(unit_test
            tests/unit/smtp_parser_test.cpp
            tests/unit/ssh_ftp_parser_test.cpp
            tests/unit/pop3_imap_http_parser_test.cpp
            tests/unit/mysql_parser_test.cpp
        )
        target_link_libraries(unit_test PRIVATE scanner_core Catch2::Catch2 Catch2::Catch2WithMain)
        target_include_directories(unit_test PRIVATE
            ${CMAKE_SOURCE_DIR}/include
        )
        target_compile_features(unit_test PRIVATE cxx_std_20)
        message(STATUS "  Catch2: ${Catch2_VERSION} (unit tests enabled)")
    else()
        message(STATUS "  Catch2: not found, unit tests disabled (brew install catch2)")
    endif()
else()
    message(STATUS "  Unit tests: disabled (ENABLE_TESTS=OFF)")
endif()

# 快速 probe 测试（手动运行）
add_executable(probe_test _unit_test.cpp)
target_link_libraries(probe_test PRIVATE scanner_core)
target_compile_features(probe_test PRIVATE cxx_std_20)

add_executable(deep_probe src/scanner/deep_probe_main.cpp)
target_link_libraries(deep_probe PRIVATE scanner_core)
target_compile_features(deep_probe PRIVATE cxx_std_20)

# =====================
# 依赖汇总
# =====================
message(STATUS "Dependency summary:")
message(STATUS "  Boost: ${Boost_VERSION}")
message(STATUS "  nlohmann_json: ${nlohmann_json_VERSION}")
message(STATUS "  fmt: ${fmt_VERSION}")
message(STATUS "  c-ares target: ${CARES_TARGET}")
