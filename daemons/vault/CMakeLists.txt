# vault daemon (owner: LNX).
add_library(pl_vault STATIC src/vault.cpp)
add_library(pl::vault ALIAS pl_vault)
target_include_directories(pl_vault PUBLIC include)
target_link_libraries(pl_vault PUBLIC nlohmann_json::nlohmann_json PkgConfig::SODIUM)
pl_target_defaults(pl_vault)

add_executable(pl-vault src/main.cpp)
target_link_libraries(pl-vault PRIVATE pl::vault pl::plcommon pl::contracts)
pl_target_defaults(pl-vault)

if(BUILD_TESTING)
  pl_add_test(vault_test SOURCES tests/vault_test.cpp LIBS pl::vault pl::contracts LABELS security)
  target_compile_definitions(vault_test PRIVATE PL_CONTRACTS_DIR="${PROJECT_SOURCE_DIR}/contracts")
endif()
