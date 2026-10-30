# WIN: Fourier helpers linked into core (scroll tracking, redaction checker...).
add_library(pl_fourier STATIC src/fourier.cpp)
add_library(pl::fourier ALIAS pl_fourier)
# L-001: WIN adopts LNX's interface header from the core shell's tree unchanged.
target_include_directories(pl_fourier PUBLIC include ${CMAKE_SOURCE_DIR}/daemons/core/shell/include)
target_link_libraries(pl_fourier PUBLIC pl::plcommon nlohmann_json::nlohmann_json)
pl_target_defaults(pl_fourier)
