cmake_minimum_required(VERSION 3.24)

project(ExtWatch
    VERSION 0.1.0
    DESCRIPTION "Local watchdog that diffs your browser extensions on every silent update"
    LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

option(EXTWATCH_BUILD_TESTS "Build unit tests" ON)
option(EXTWATCH_MACOS_BUNDLE "Build the macOS app as a .app bundle (packaging)" OFF)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Gui Widgets Sql Concurrent Network Svg)
qt_standard_project_setup()

include(deps)

add_subdirectory(src)

if(EXTWATCH_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
