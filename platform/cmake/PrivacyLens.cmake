# Shared CMake settings and helpers (owner: LNX). Included by the root CMakeLists.txt.
include_guard(GLOBAL)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(PL_FUZZ "Build libFuzzer targets (clang only; use the fuzz preset)" OFF)
option(PL_WERROR "Treat warnings as errors" ON)

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  set(CMAKE_C_COMPILER_LAUNCHER ${CCACHE_PROGRAM})
  set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE_PROGRAM})
endif()

include(CTest)
include(GoogleTest)
find_package(GTest REQUIRED)
find_package(nlohmann_json 3.11 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

# pl_target_defaults(<target>): warnings, -Werror, hardening for our own code.
function(pl_target_defaults tgt)
  target_compile_options(${tgt} PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion
    -Wsign-conversion -Wnon-virtual-dtor -Wold-style-cast -Wcast-align -Woverloaded-virtual
    -Wnull-dereference -Wdouble-promotion -Wformat=2 -Wimplicit-fallthrough
    $<$<BOOL:${PL_WERROR}>:-Werror>)
  if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(${tgt} PRIVATE _FORTIFY_SOURCE=3)
  endif()
  target_compile_options(${tgt} PRIVATE -fstack-protector-strong -fstack-clash-protection)
endfunction()

# pl_add_test(<name> SOURCES ... LIBS ... [LABELS ...]): a GoogleTest executable.
function(pl_add_test name)
  cmake_parse_arguments(T "" "" "SOURCES;LIBS;LABELS" ${ARGN})
  add_executable(${name} ${T_SOURCES})
  pl_target_defaults(${name})
  target_link_libraries(${name} PRIVATE ${T_LIBS} GTest::gtest GTest::gtest_main GTest::gmock)
  gtest_discover_tests(${name} PROPERTIES LABELS "unit;${T_LABELS}" DISCOVERY_TIMEOUT 60)
endfunction()

# pl_add_fuzzer(<name> SOURCES ... LIBS ... CORPUS <dir>): a libFuzzer target.
# fuzz.sh finds every target through the PL_FUZZERS global property.
function(pl_add_fuzzer name)
  cmake_parse_arguments(F "" "CORPUS" "SOURCES;LIBS" ${ARGN})
  if(NOT PL_FUZZ)
    return()
  endif()
  add_executable(${name} ${F_SOURCES})
  pl_target_defaults(${name})
  target_compile_options(${name} PRIVATE -fsanitize=fuzzer)
  target_link_options(${name} PRIVATE -fsanitize=fuzzer)
  target_link_libraries(${name} PRIVATE ${F_LIBS})
  set_property(GLOBAL APPEND PROPERTY PL_FUZZERS "${name}|$<TARGET_FILE:${name}>|${F_CORPUS}")
endfunction()

# Write the fuzzer list once everything is configured.
function(pl_write_fuzzer_list)
  get_property(fuzzers GLOBAL PROPERTY PL_FUZZERS)
  string(REPLACE ";" "\n" lines "${fuzzers}")
  file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/pl_fuzzers.txt" CONTENT "${lines}\n")
endfunction()
cmake_language(DEFER DIRECTORY ${CMAKE_SOURCE_DIR} CALL pl_write_fuzzer_list)
