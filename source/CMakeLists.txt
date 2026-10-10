cmake_minimum_required(VERSION 3.16)
project(craft DESCRIPTION "Certificate Request Agent For Tickets" LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# An unoptimized default build would silently leave _FORTIFY_SOURCE inactive.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Installation layout compiled into the binaries; packaged builds typically use /usr/bin and /usr/libexec.
set(CRAFT_CONFIG_DIR "/etc/craft" CACHE STRING "Root-owned configuration directory")
set(CRAFT_RUNTIME_DIR "/run/craft" CACHE STRING "Service account's private runtime directory")
set(CRAFT_LAUNCHER "/usr/local/bin/craft" CACHE STRING "Installed path of the launcher")
set(CRAFT_WORKER "/usr/local/libexec/craft-worker" CACHE STRING "Installed path of the worker")

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
  message(FATAL_ERROR "C++20 library support for format, spans and ranges is required: GCC/libstdc++ 13.1 or "
                      "newer. On RHEL 8 and 9 build with gcc-toolset-13 or later, for example "
                      "`scl enable gcc-toolset-13 -- cmake ...`.")
endif()

# Dependency floors are those of RHEL 8. The maintainer needs only Kerberos.
find_package(PkgConfig REQUIRED)
pkg_check_modules(KRB5 REQUIRED IMPORTED_TARGET krb5)
pkg_check_modules(WORKER REQUIRED IMPORTED_TARGET openssl>=1.1.1 libcurl>=7.61 libxml-2.0>=2.9 libsasl2)

# Red Hat backported krb5_marshal_credentials (upstream 1.20) to 1.18.2, so test for the symbol, not a version.
include(CheckCXXSymbolExists)
set(CMAKE_REQUIRED_INCLUDES ${KRB5_INCLUDE_DIRS})
set(CMAKE_REQUIRED_LIBRARIES ${KRB5_LINK_LIBRARIES})
check_cxx_symbol_exists(krb5_marshal_credentials krb5.h CRAFT_HAS_KRB5_MARSHAL)
unset(CMAKE_REQUIRED_INCLUDES)
unset(CMAKE_REQUIRED_LIBRARIES)
if(NOT CRAFT_HAS_KRB5_MARSHAL)
  message(FATAL_ERROR "MIT Kerberos with krb5_marshal_credentials is required (1.20, or RHEL 8.5+/9.0+).")
endif()

# OpenLDAP ships pkg-config files only from 2.5; RHEL 8 has 2.4.
add_library(craft-ldap INTERFACE)
pkg_check_modules(LDAP IMPORTED_TARGET ldap)
if(LDAP_FOUND)
  target_link_libraries(craft-ldap INTERFACE PkgConfig::LDAP)
else()
  find_path(LDAP_INCLUDE_DIR ldap.h)
  find_library(LDAP_LIBRARY ldap)
  if(NOT LDAP_INCLUDE_DIR OR NOT LDAP_LIBRARY)
    message(FATAL_ERROR "OpenLDAP client development files (ldap.h, libldap) are required.")
  endif()
  target_include_directories(craft-ldap INTERFACE ${LDAP_INCLUDE_DIR})
  target_link_libraries(craft-ldap INTERFACE ${LDAP_LIBRARY})
endif()

include(CheckPIESupported)
check_pie_supported()
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_compile_options(-Wall -Wextra -Wpedantic -Wformat=2 -Wformat-security -Werror=format-security
                    -fstack-protector-strong -fstack-clash-protection
                    "$<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE>" "$<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=2>")
add_compile_definitions(_GNU_SOURCE _GLIBCXX_ASSERTIONS
                        CRAFT_CONFIG_DIR="${CRAFT_CONFIG_DIR}" CRAFT_RUNTIME_DIR="${CRAFT_RUNTIME_DIR}"
                        CRAFT_LAUNCHER="${CRAFT_LAUNCHER}" CRAFT_WORKER="${CRAFT_WORKER}")
add_link_options(-Wl,-z,relro,-z,now,-z,noexecstack)

add_executable(craft src/launcher.cpp)
add_executable(craft-worker src/worker.cpp)
add_executable(craft-maintain src/maintain.cpp)
target_link_libraries(craft-worker PRIVATE PkgConfig::KRB5 PkgConfig::WORKER craft-ldap)
target_link_libraries(craft-maintain PRIVATE PkgConfig::KRB5)

# The optional wrapper names the configured launcher; emit it executable whatever mode the checkout recorded.
configure_file(scripts/with-craft.in "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/with-craft" @ONLY NEWLINE_STYLE UNIX)
file(COPY "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/with-craft" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}"
     FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

include(CTest)
if(BUILD_TESTING)
  add_executable(craft-tests tests/tests.cpp)
  target_link_libraries(craft-tests PRIVATE PkgConfig::KRB5 PkgConfig::WORKER craft-ldap)
  target_link_options(craft-tests PRIVATE -Wl,--wrap=krb5_get_renewed_creds)
  add_test(NAME offline-tests COMMAND craft-tests)
  add_executable(craft-key-trust-tests tests/key-trust.cpp)
  target_link_libraries(craft-key-trust-tests PRIVATE PkgConfig::KRB5 PkgConfig::WORKER craft-ldap)
  target_link_options(craft-key-trust-tests PRIVATE
    -Wl,--wrap=ldap_initialize,--wrap=ldap_set_option,--wrap=ldap_sasl_interactive_bind_s
    -Wl,--wrap=ldap_modify_ext_s,--wrap=ldap_unbind_ext_s)
  add_test(NAME key-trust-cleanup COMMAND craft-key-trust-tests)

  # Integration harness for a disposable container only; tests/run-container-tests.sh installs and runs it.
  # The second maintainer is forced onto the /proc watch that kernels without pidfd_open (RHEL 8) use.
  add_executable(craft-maintain-proc src/maintain.cpp)
  target_compile_definitions(craft-maintain-proc PRIVATE CRAFT_USE_PIDFD=false)
  target_link_libraries(craft-maintain-proc PRIVATE PkgConfig::KRB5)
  add_executable(craft-maintain-tests tests/maintain-integration.cpp)
endif()
# Intentionally no automatic setuid install target. Review before privileged install.
