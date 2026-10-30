# core runtime (owner: LNX): CDP client, capture model, actuator validation, daemon.
add_library(pl_core_runtime STATIC src/cdp.cpp src/capture.cpp src/actuator.cpp)
add_library(pl::core_runtime ALIAS pl_core_runtime)
target_include_directories(pl_core_runtime PUBLIC include)
target_link_libraries(pl_core_runtime PUBLIC pl::core_detect_iface pl::plcommon pl::gate)
pl_target_defaults(pl_core_runtime)

add_executable(pl-core src/main.cpp)
target_link_libraries(pl-core PRIVATE pl::core_runtime pl::contracts)
pl_target_defaults(pl-core)

# TODO(resume): unit tests for capture/actuator (tests/capture_test.cpp) not written yet.
