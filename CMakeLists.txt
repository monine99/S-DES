# =============================================================================
#  CMakeLists.txt —— S-DES 加解密程序
#
#  构建三个目标：
#      sdes_core  —— 纯 C++ 的算法核心库（不依赖 Qt，可被命令行/图形界面/测试共用）
#      sdes-cli   —— 命令行工具，覆盖作业五关
#      test-sdes  —— 自测程序
#      sdes_gui   —— Qt 6 图形界面（未安装 Qt 时自动跳过，不影响其它目标）
#
#  用法：
#      cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
#      cmake --build build -j
# =============================================================================

cmake_minimum_required(VERSION 3.16)
project(SDes VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 未指定构建类型时默认 Release
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "构建类型" FORCE)
endif()

if(MSVC)
    # /utf-8 让 MSVC 正确读取 UTF-8 源码里的中文注释与字符串
    add_compile_options(/utf-8 /W4)
else()
    add_compile_options(-Wall -Wextra)
endif()

# -----------------------------------------------------------------------------
#  核心算法库（不依赖 Qt）
# -----------------------------------------------------------------------------
add_library(sdes_core STATIC
    src/key_schedule.cpp
    src/cipher.cpp
    src/brute_force.cpp
    src/analysis.cpp
)

target_include_directories(sdes_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

find_package(Threads REQUIRED)
target_link_libraries(sdes_core PUBLIC Threads::Threads)

# -----------------------------------------------------------------------------
#  自测程序
# -----------------------------------------------------------------------------
add_executable(sdes_tests tests/test_sdes.cpp)
target_link_libraries(sdes_tests PRIVATE sdes_core)
set_target_properties(sdes_tests PROPERTIES OUTPUT_NAME test-sdes)

# -----------------------------------------------------------------------------
#  命令行工具
# -----------------------------------------------------------------------------
add_executable(sdes_cli apps/cli/main.cpp)
target_link_libraries(sdes_cli PRIVATE sdes_core)
set_target_properties(sdes_cli PROPERTIES OUTPUT_NAME sdes-cli)

# -----------------------------------------------------------------------------
#  Qt 6 图形界面（可选目标）
# -----------------------------------------------------------------------------
find_package(Qt6 QUIET COMPONENTS Widgets)

if(Qt6_FOUND)
    set(CMAKE_AUTOMOC ON)

    add_executable(sdes_gui WIN32
        apps/gui/main.cpp
        apps/gui/main_window.cpp
        apps/gui/main_window.hpp
    )
    target_link_libraries(sdes_gui PRIVATE sdes_core Qt6::Widgets)
    set_target_properties(sdes_gui PROPERTIES OUTPUT_NAME sdes-gui)

    message(STATUS "已找到 Qt ${Qt6_VERSION}，将构建图形界面 sdes_gui")
else()
    message(STATUS "未找到 Qt6，只构建核心库 / 自测程序 / 命令行工具；图形界面已跳过")
    message(STATUS "如需图形界面，请安装 Qt 6 后重新配置，或用 Qt Creator 直接打开本文件")
endif()

# -----------------------------------------------------------------------------
#  便捷测试目标：ctest 或 `cmake --build build --target run-tests`
# -----------------------------------------------------------------------------
enable_testing()
add_test(NAME sdes_selftest COMMAND sdes_tests)
add_custom_target(run-tests
    COMMAND $<TARGET_FILE:sdes_tests>
    DEPENDS sdes_tests
    USES_TERMINAL
)
