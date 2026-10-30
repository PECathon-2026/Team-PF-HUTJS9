# WIN: sanitize v1 (placeholders via the vault callback, field boxes, PNG re-encode, channel scrubbing).
# The dev image ships OpenCV's libraries and headers without a CMake config: find them directly.
find_path(PL_OPENCV_INC opencv2/core.hpp PATH_SUFFIXES opencv4 REQUIRED)
foreach(m core imgproc imgcodecs)
  find_library(PL_OPENCV_${m} opencv_${m} REQUIRED)
endforeach()
add_library(pl_sanitize STATIC src/sanitizer.cpp)
add_library(pl::sanitize ALIAS pl_sanitize)
target_include_directories(pl_sanitize PUBLIC include ${CMAKE_SOURCE_DIR}/daemons/core/shell/include)
target_include_directories(pl_sanitize SYSTEM PRIVATE ${PL_OPENCV_INC})
target_link_libraries(pl_sanitize PUBLIC pl::plcommon nlohmann_json::nlohmann_json PRIVATE ${PL_OPENCV_imgcodecs} ${PL_OPENCV_imgproc} ${PL_OPENCV_core})
pl_target_defaults(pl_sanitize)

if(BUILD_TESTING)
  pl_add_test(win_sanitize_test SOURCES tests/sanitize_test.cpp LIBS pl::sanitize pl::detect LABELS win)
  target_compile_options(win_sanitize_test PRIVATE -Wno-missing-field-initializers)  # designated initializers in test fixtures
endif()
