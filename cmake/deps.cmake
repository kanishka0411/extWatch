# Third-party dependencies. tree-sitter, its JavaScript grammar and dtl are fetched at
# configure time and compiled as static libraries; miniz is vendored in third_party/.
include(FetchContent)
set(FETCHCONTENT_QUIET OFF)

FetchContent_Declare(tree_sitter
    GIT_REPOSITORY https://github.com/tree-sitter/tree-sitter.git
    GIT_TAG        v0.26.13
    GIT_SHALLOW    TRUE
    SOURCE_SUBDIR  .cmake-disabled)   # never add_subdirectory: we compile lib.c ourselves

FetchContent_Declare(tree_sitter_javascript
    GIT_REPOSITORY https://github.com/tree-sitter/tree-sitter-javascript.git
    GIT_TAG        v0.25.0
    GIT_SHALLOW    TRUE
    SOURCE_SUBDIR  .cmake-disabled)

FetchContent_Declare(dtl
    GIT_REPOSITORY https://github.com/cubicdaiya/dtl.git
    GIT_TAG        v1.21
    GIT_SHALLOW    TRUE
    SOURCE_SUBDIR  .cmake-disabled)

FetchContent_MakeAvailable(tree_sitter tree_sitter_javascript dtl)

# tree-sitter runtime (C)
add_library(tree_sitter STATIC "${tree_sitter_SOURCE_DIR}/lib/src/lib.c")
target_include_directories(tree_sitter
    PUBLIC  "${tree_sitter_SOURCE_DIR}/lib/include"
    PRIVATE "${tree_sitter_SOURCE_DIR}/lib/src" "${tree_sitter_SOURCE_DIR}/lib/src/wasm")
if(NOT WIN32)
    target_compile_definitions(tree_sitter PRIVATE _POSIX_C_SOURCE=200112L _DEFAULT_SOURCE)
endif()
set_target_properties(tree_sitter PROPERTIES C_STANDARD 11 POSITION_INDEPENDENT_CODE ON)

# tree-sitter-javascript grammar (generated C)
add_library(tree_sitter_javascript STATIC
    "${tree_sitter_javascript_SOURCE_DIR}/src/parser.c"
    "${tree_sitter_javascript_SOURCE_DIR}/src/scanner.c")
target_include_directories(tree_sitter_javascript PRIVATE "${tree_sitter_javascript_SOURCE_DIR}/src")
target_link_libraries(tree_sitter_javascript PUBLIC tree_sitter)
set_target_properties(tree_sitter_javascript PROPERTIES C_STANDARD 11 POSITION_INDEPENDENT_CODE ON)

# dtl (header-only diff library)
add_library(dtl INTERFACE)
target_include_directories(dtl INTERFACE "${dtl_SOURCE_DIR}")

# miniz (vendored single-file zip library)
add_library(miniz STATIC "${CMAKE_SOURCE_DIR}/third_party/miniz/miniz.c")
target_include_directories(miniz PUBLIC "${CMAKE_SOURCE_DIR}/third_party/miniz")
target_compile_definitions(miniz PUBLIC MINIZ_NO_ZLIB_COMPATIBLE_NAMES)
set_target_properties(miniz PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Third-party code is compiled with warnings off; our own code opts into -Wall via extwatch_warnings.
foreach(tp tree_sitter tree_sitter_javascript miniz)
    if(MSVC)
        target_compile_options(${tp} PRIVATE /w)
    else()
        target_compile_options(${tp} PRIVATE -w)
    endif()
endforeach()
