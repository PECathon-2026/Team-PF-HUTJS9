# WIN: detect v1 (normalise, patterns + validators via Hyperscan, structural, split re-join).
pkg_check_modules(HS REQUIRED IMPORTED_TARGET libhs)
add_library(pl_detect STATIC src/normalize.cpp src/scanner.cpp src/detector.cpp)
add_library(pl::detect ALIAS pl_detect)
target_include_directories(pl_detect PUBLIC include ${CMAKE_SOURCE_DIR}/daemons/core/shell/include)
target_link_libraries(pl_detect PUBLIC pl::plcommon pl::fourier nlohmann_json::nlohmann_json PRIVATE PkgConfig::HS)
pl_target_defaults(pl_detect)

if(BUILD_TESTING)
  pl_add_test(win_detect_test SOURCES tests/detect_test.cpp LIBS pl::detect LABELS win)
  target_compile_options(win_detect_test PRIVATE -Wno-missing-field-initializers)  # designated initializers in test fixtures
endif()
