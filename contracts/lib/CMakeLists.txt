# C++ contract validator (owner: LNX).
find_package(nlohmann_json_schema_validator REQUIRED)

add_library(pl_contracts STATIC cpp/src/registry.cpp)
add_library(pl::contracts ALIAS pl_contracts)
target_include_directories(pl_contracts PUBLIC cpp/include)
target_link_libraries(pl_contracts PUBLIC nlohmann_json::nlohmann_json pl::plcommon
  PRIVATE nlohmann_json_schema_validator::validator)
pl_target_defaults(pl_contracts)

if(BUILD_TESTING)
  pl_add_test(pl_contracts_test SOURCES cpp/tests/registry_test.cpp LIBS pl::contracts LABELS contracts)
  target_compile_definitions(pl_contracts_test PRIVATE PL_CONTRACTS_DIR="${PROJECT_SOURCE_DIR}/contracts")
endif()
