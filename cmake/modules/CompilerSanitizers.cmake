# CompilerSanitizers.cmake
#
# Provides CMake options to enable memory/thread/UB sanitizers.
# Usage:
#   cmake -B build-asan -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASAN=ON -DENABLE_UBSAN=ON
#   cmake --build build-asan
#
# Notes:
#   - ASAN and TSAN are mutually exclusive; CMake will error if both are ON.
#   - Link flags are added globally so all targets (lib + tests) are instrumented.
#   - Not supported on MSVC (silently ignored on Windows builds).
#   - WASM builds: Emscripten has its own -fsanitize flags; these options are
#     ignored when EMSCRIPTEN is set to avoid incompatible flag injection.

option(ENABLE_ASAN  "Build with AddressSanitizer (-fsanitize=address,leak)"     OFF)
option(ENABLE_UBSAN "Build with UndefinedBehaviorSanitizer (-fsanitize=undefined)" OFF)
option(ENABLE_TSAN  "Build with ThreadSanitizer (-fsanitize=thread)"             OFF)

if(EMSCRIPTEN)
    # Emscripten manages its own sanitizer flags; skip injection.
    return()
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # MSVC uses /fsanitize=address separately; out of scope for this module.
    return()
endif()

# Mutual exclusion check
if(ENABLE_ASAN AND ENABLE_TSAN)
    message(FATAL_ERROR
        "ENABLE_ASAN and ENABLE_TSAN are mutually exclusive — "
        "AddressSanitizer and ThreadSanitizer cannot be used together.")
endif()

# Collect flags
set(_SANITIZER_FLAGS "")
set(_SANITIZER_NAMES "")

if(ENABLE_ASAN)
    list(APPEND _SANITIZER_FLAGS "-fsanitize=address,leak" "-fno-omit-frame-pointer")
    list(APPEND _SANITIZER_NAMES "ASAN")
endif()

if(ENABLE_UBSAN)
    list(APPEND _SANITIZER_FLAGS "-fsanitize=undefined" "-fno-omit-frame-pointer")
    list(APPEND _SANITIZER_NAMES "UBSAN")
endif()

if(ENABLE_TSAN)
    list(APPEND _SANITIZER_FLAGS "-fsanitize=thread" "-fno-omit-frame-pointer")
    list(APPEND _SANITIZER_NAMES "TSAN")
endif()

if(_SANITIZER_FLAGS)
    string(JOIN "+" _SANITIZER_LABEL ${_SANITIZER_NAMES})
    message(STATUS "Sanitizers enabled: ${_SANITIZER_LABEL}")

    # Add compile + link flags project-wide
    add_compile_options(${_SANITIZER_FLAGS})
    add_link_options(${_SANITIZER_FLAGS})
endif()
