cmake_minimum_required(VERSION 3.10)
project(protocol_scanner LANGUAGES CXX VERSION 1.0.0)

# =====================
# 构建配置
# =====================
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build: Debug/Release" FORCE)
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# C++ 标准
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Debug/Release 模式编译器优化
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -DDEBUG -fno-omit-frame-pointer" CACHE STRING "Flags used by C++ compiler during DEBUG builds" FORCE)
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -march=native" CACHE STRING "Flags used by C++ compiler during RELEASE builds" FORCE)

# 全局编译选项
add_compile_options(-Wall -Wextra -Wno-unused-parameter)

# 在 Clang/GCC 下开启彩色诊断
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    add_compile_options(-fdiagnostics-color=auto)
endif()

# 性能优化开关
option(ENABLE_PERFORMANCE_MODE "Enable performance optimizations" ON)
if(ENABLE_PERFORMANCE_MODE)
    add_compile_options(-flto)
    add_definitions(-DENABLE_INLINE_PROTOCOLS)
endif()

# macOS 常见包管理前缀，便于 find_package 找到 Homebrew 安装
if(APPLE)
    list(APPEND CMAKE_PREFIX_PATH /opt/homebrew /usr/local)
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
find_package(Boost COMPONENTS system program_options filesystem QUIET)
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

# c-ares DNS
set(CARES_TARGET "")
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
    set(_cares_help "c-ares not found. ${_mac_hint}; ${_deb_hint}")
    message(FATAL_ERROR "${_cares_help}")
endif()

# =====================
# 源文件与包含目录
# =====================
set(SCANNER_SRCS
    ${CMAKE_SOURCE_DIR}/src/scanner/main.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/dns_resolver.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/common/thread_pool.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/common/io_thread_pool.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/core/session.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/utils.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/scanner.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/vendor/vendor_detector.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/output/result_handler.cpp
    # ${CMAKE_SOURCE_DIR}/src/scanner/port_scanner.cpp
)

set(PROTOCOL_SRCS
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/smtp_protocol.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/pop3_protocol.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/imap_protocol.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/http_protocol.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/ftp_protocol.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/telnet_protocol.cpp
    ${CMAKE_SOURCE_DIR}/src/scanner/protocols/ssh_protocol.cpp
)

set(ALL_SRCS ${SCANNER_SRCS} ${PROTOCOL_SRCS})

add_executable(scanner ${ALL_SRCS})

# 项目内头文件
target_include_directories(scanner PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/OuterLib
)

# =====================
# 链接库
# =====================
if(TARGET Boost::system AND TARGET Boost::program_options)
    target_link_libraries(scanner PRIVATE Boost::system Boost::program_options Boost::filesystem)
else()
    target_link_libraries(scanner PRIVATE ${Boost_LIBRARIES})
endif()

target_link_libraries(scanner PRIVATE Threads::Threads)

# fmt (spdlog 依赖)
find_package(fmt CONFIG QUIET)
if(TARGET fmt::fmt)
    target_link_libraries(scanner PRIVATE fmt::fmt)
endif()

# nlohmann/json
if(JSON_TARGET)
    target_link_libraries(scanner PRIVATE ${JSON_TARGET})
endif()

if(NOT ENABLE_LOGGING)
    target_compile_definitions(scanner PRIVATE SCANNER_DISABLE_LOGGING)
endif()

# c-ares linking
target_link_libraries(scanner PRIVATE ${CARES_TARGET})

# 要求特性
target_compile_features(scanner PRIVATE cxx_std_20)

# =====================
# 安装规则
# =====================
install(TARGETS scanner RUNTIME DESTINATION bin)
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
# 依赖汇总
# =====================
message(STATUS "Dependency summary:")
message(STATUS "  Boost: ${Boost_VERSION}")
message(STATUS "  nlohmann_json: ${nlohmann_json_VERSION}")
message(STATUS "  fmt: ${fmt_VERSION}")
message(STATUS "  c-ares target: ${CARES_TARGET}")
