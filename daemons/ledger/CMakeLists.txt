# ledger (owner: WIN-B). Metadata-only event bus, segments, stream endpoint.
add_library(ledgerlib STATIC src/reject.cpp src/segment.cpp src/merkle.cpp src/audit.cpp src/ledger.cpp src/server.cpp)
add_library(pl::ledgerlib ALIAS ledgerlib)
target_include_directories(ledgerlib PUBLIC include)
target_link_libraries(ledgerlib PUBLIC pl::plcommon pl::contracts PkgConfig::SODIUM)
pl_target_defaults(ledgerlib)

add_executable(ledgerd src/main.cpp)
pl_target_defaults(ledgerd)
target_link_libraries(ledgerd PRIVATE pl::ledgerlib)

add_executable(pl-audit src/audit_main.cpp)
pl_target_defaults(pl-audit)
target_link_libraries(pl-audit PRIVATE pl::ledgerlib)

if(BUILD_TESTING)
  pl_add_test(ledger_test SOURCES tests/reject_test.cpp tests/segment_test.cpp tests/ledger_test.cpp tests/merkle_test.cpp
              LIBS pl::ledgerlib LABELS ledger)
  target_compile_definitions(ledger_test PRIVATE PL_CONTRACTS_DIR="${PROJECT_SOURCE_DIR}/contracts")
endif()
