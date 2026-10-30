# WIN-B: ledger make targets (owner: WIN-B). Included from the WIN-B fence in mk/win.mk
# once that file is on main; until then: make -f Makefile -f daemons/ledger/ledger.mk <target>
.PHONY: ledger-test ledger-asan
ledger-test: dev-image
	$(IN_DEV) bash -c 'cmake --preset debug >/dev/null && cmake --build --preset debug --target ledger_test ledgerd && ctest --preset debug -L ledger --output-on-failure'
ledger-asan: dev-image
	$(IN_DEV) bash -c 'cmake --preset asan >/dev/null && cmake --build --preset asan --target ledger_test && ctest --preset asan -L ledger --output-on-failure'
