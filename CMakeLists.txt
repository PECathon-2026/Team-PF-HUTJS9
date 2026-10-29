# PrivacyLens root CMake project (owner: LNX). Configure through CMakePresets.json.
cmake_minimum_required(VERSION 3.28)
project(PrivacyLens VERSION 0.0.0 LANGUAGES C CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/platform/cmake")
include(PrivacyLens)

# Component folders are added only when they contain a CMakeLists.txt, so each
# machine's folders are picked up as soon as they exist. WIN's core libraries
# come before daemons/core so the core shell can detect their targets
# (`if(TARGET ...)`) and fall back to its NullDetector otherwise.
set(PL_COMPONENT_DIRS
  libs/plcommon
  contracts/lib
  daemons/core/detect
  daemons/core/sanitize
  daemons/core/fourier
  daemons/core
  daemons/vault
  daemons/gate
  daemons/ledger
  platform
)
foreach(dir IN LISTS PL_COMPONENT_DIRS)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${dir}/CMakeLists.txt")
    message(STATUS "PrivacyLens: adding ${dir}")
    add_subdirectory(${dir})
  endif()
endforeach()
