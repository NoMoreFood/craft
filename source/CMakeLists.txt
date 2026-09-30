cmake_minimum_required(VERSION 3.16)
project(craft DESCRIPTION "Certificate Request Agent For Tickets" LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Fail early when the compiler library lacks the required C++20 facilities.
include(CheckCXXSourceCompiles)
check_cxx_source_compiles("
#include <algorithm>
#include <array>
#include <concepts>
#include <format>
#include <ranges>
#include <span>
int main() {
    std::array values{1, 2};
    std::span<const int> view(values);
    return std::format(\"{}\", std::ranges::count(view, 1)).empty();
}" CRAFT_HAS_CXX20_LIBRARY)
if(NOT CRAFT_HAS_CXX20_LIBRARY)
  message(FATAL_ERROR "C++20 library support for format, spans, and ranges is required (GCC/libstdc++ 13.1+ or equivalent).")
endif()
find_package(PkgConfig REQUIRED)
pkg_check_modules(DEPS REQUIRED IMPORTED_TARGET openssl>=3.0 krb5>=1.19 libcurl>=7.62 libxml-2.0>=2.9 ldap libsasl2)
add_compile_options(-Wall -Wextra -Wpedantic -Wformat=2 -Wformat-security -Werror=format-security -fstack-protector-strong -fPIE)
add_compile_definitions(_GNU_SOURCE _FORTIFY_SOURCE=2)
add_link_options(-pie -Wl,-z,relro,-z,now,-z,noexecstack)
add_executable(craft src/launcher.cpp)
add_executable(craft-worker src/worker.cpp)
add_executable(craft-maintain src/maintain.cpp)
target_link_libraries(craft-maintain PRIVATE PkgConfig::DEPS)
target_link_libraries(craft-worker PRIVATE PkgConfig::DEPS)
include(CTest)
if(BUILD_TESTING)
  add_executable(craft-tests tests/tests.cpp)
  add_executable(craft-maintain-tests tests/maintain-integration.cpp)
  add_dependencies(craft-maintain-tests craft-maintain craft-tests)
  target_link_libraries(craft-tests PRIVATE PkgConfig::DEPS)
  add_test(NAME offline-tests COMMAND craft-tests)
endif()
# Intentionally no automatic setuid install target. Review before privileged install.
