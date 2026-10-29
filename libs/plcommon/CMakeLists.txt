# plcommon (owner: LNX).
add_library(plcommon STATIC src/frame.cpp src/uds.cpp src/validate.cpp src/scrub.cpp src/taint.cpp src/ids.cpp src/log.cpp)
add_library(pl::plcommon ALIAS plcommon)
target_include_directories(plcommon PUBLIC include)
target_link_libraries(plcommon PUBLIC nlohmann_json::nlohmann_json)
pl_target_defaults(plcommon)

if(BUILD_TESTING)
  pl_add_test(plcommon_test
    SOURCES tests/frame_test.cpp tests/uds_test.cpp tests/validate_test.cpp tests/scrub_test.cpp
            tests/taint_test.cpp tests/ids_test.cpp tests/log_test.cpp
    LIBS pl::plcommon)
  target_compile_definitions(plcommon_test PRIVATE PL_TESTDATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/testdata")
  find_package(rapidcheck CONFIG REQUIRED)
  target_link_libraries(plcommon_test PRIVATE rapidcheck)
endif()

find_package(benchmark QUIET)
if(benchmark_FOUND AND NOT PL_FUZZ)
  add_executable(plcommon_bench bench/plcommon_bench.cpp)
  pl_target_defaults(plcommon_bench)
  target_link_libraries(plcommon_bench PRIVATE pl::plcommon benchmark::benchmark benchmark::benchmark_main)
endif()

pl_add_fuzzer(fuzz_frame_decoder SOURCES fuzz/fuzz_frame_decoder.cpp LIBS pl::plcommon CORPUS ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/frame)
pl_add_fuzzer(fuzz_scrub SOURCES fuzz/fuzz_scrub.cpp LIBS pl::plcommon CORPUS ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/scrub)
