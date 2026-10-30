# gate daemon (owner: LNX). Must not link anything from daemons/core/detect (AD-11).
add_library(pl_gate STATIC src/scanner.cpp src/ai_lane.cpp src/http.cpp)
add_library(pl::gate ALIAS pl_gate)
target_include_directories(pl_gate PUBLIC include)
target_link_libraries(pl_gate PUBLIC pl::plcommon nlohmann_json::nlohmann_json PkgConfig::SODIUM)
pl_target_defaults(pl_gate)

add_executable(pl-gate src/main.cpp)
target_link_libraries(pl-gate PRIVATE pl::gate pl::contracts)
pl_target_defaults(pl-gate)

if(BUILD_TESTING)
  pl_add_test(gate_test SOURCES tests/scanner_test.cpp tests/ai_lane_test.cpp tests/http_test.cpp
    LIBS pl::gate pl::contracts LABELS security)
  target_compile_definitions(gate_test PRIVATE PL_CONTRACTS_DIR="${PROJECT_SOURCE_DIR}/contracts")
endif()

pl_add_fuzzer(fuzz_gate_decoder SOURCES fuzz/fuzz_gate_decoder.cpp LIBS pl::gate
  CORPUS ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus)
