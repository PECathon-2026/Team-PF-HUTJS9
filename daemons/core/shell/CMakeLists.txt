# core shell: detect/sanitize interface and the fail-closed fallback (owner: LNX).
add_library(pl_core_detect_iface STATIC src/null_detector.cpp src/detect_api.cpp)
add_library(pl::core_detect_iface ALIAS pl_core_detect_iface)
target_include_directories(pl_core_detect_iface PUBLIC include)
target_link_libraries(pl_core_detect_iface PUBLIC pl::plcommon)
pl_target_defaults(pl_core_detect_iface)

# Use WIN's implementations when their CMake targets exist (request L-001).
if(TARGET pl::detect AND TARGET pl::sanitize)
  message(STATUS "core: linking WIN's pl::detect and pl::sanitize")
  target_link_libraries(pl_core_detect_iface PUBLIC pl::detect pl::sanitize)
  target_compile_definitions(pl_core_detect_iface PUBLIC PL_HAVE_WIN_DETECT=1)
else()
  message(STATUS "core: WIN's pl::detect/pl::sanitize not present; using the fail-closed NullDetector")
endif()

if(BUILD_TESTING)
  pl_add_test(core_detect_iface_test SOURCES tests/null_detector_test.cpp LIBS pl::core_detect_iface)
endif()
