# core daemon (owner: LNX). WIN's detect/sanitize/fourier folders are added by the
# root CMakeLists.txt before this one, so their targets are visible here. The
# runtime links the gate's scanner (LNX code) for the plain-text fill check, so
# daemons/gate must be configured first.
add_subdirectory(shell)
