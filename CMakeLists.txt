cmake_minimum_required(VERSION 3.5)

# Build Options
option(BUILD_TESTS "Compile tests along with libraries" OFF)
option(DISABLE_NON_PAGED_MEMORY "Disable non-paged memory for secure storage" OFF)
option(DISABLE_VISIBILITY "Disables and unsets -fvisibility=hidden" OFF)
option(ENABLE_64bit "Enable 64-bit compiling" OFF)
option(ENABLE_ECC "Enable support for ECC" ON)
option(ENABLE_GOST "Enable support for GOST" ON)
option(ENABLE_FIPS "Enable support for FIPS 140-2 mode" OFF)
option(ENABLE_P11_KIT "Enable p11-kit integration" ON)
option(ENABLE_PEDANTIC "Enable pedantic compile mode" OFF)
option(ENABLE_STRICT "Enable strict compile mode" ON)
option(ENABLE_SHARED "Build shared libraries" ON)
option(ENABLE_STATIC "Build static libraries" ON)
option(WITH_BOTAN "Compile with support of BOTAN" OFF)
option(WITH_OBJECTSTORE_BACKEND_DB "Build with object store backend database (SQLite3)" OFF)
option(WITH_MIGRATE "Build migration tool. Requires SQLite3." OFF)
option(WITH_OPENSSL "Compile with support of OpenSSL" ON)
option(WITH_P11_KIT "Build with p11-kit module" OFF)
option(WITH_SQLITE3 "Compiles with support of SQLite3" OFF)

include(GNUInstallDirs)

set(DEFAULT_LOG_LEVEL "INFO"
    CACHE STRING "The default log level")
set(DEFAULT_OBJECTSTORE_BACKEND "file"
    CACHE STRING "Default storage backend for token objects")
set(DEFAULT_PKCS11_LIB "${CMAKE_INSTALL_LIBDIR}/softhsm/libsofthsm2.so"
    CACHE STRING "The default PKCS#11 library")
set(DEFAULT_SOFTHSM2_CONF "${CMAKE_INSTALL_SYSCONFDIR}/softhsm2.conf"
    CACHE STRING "The default location of softhsm.conf")
set(DEFAULT_TOKENDIR "${CMAKE_INSTALL_LOCALSTATEDIR}/lib/softhsm/tokens/"
    CACHE STRING "The default location of the token directory")

set(MAX_PIN_LEN 255 CACHE STRING "Maximum PIN length")
set(MIN_PIN_LEN 4 CACHE STRING "Minimum PIN length")

set(VERSION "2.5.0")
set(VERSION_MAJOR 2)
set(VERSION_MINOR 5)
set(VERSION_PATCH 0)

set(PACKAGE "softhsm")
set(PACKAGE_BUGREPORT)
set(PACKAGE_NAME "SoftHSM")
set(PACKAGE_VERSION "${VERSION}")
set(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}")
set(PACKAGE_TARNAME "${PACKAGE}")
set(PACKAGE_URL)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Default build type for SoftHSMv2 project" FORCE)
endif(NOT CMAKE_BUILD_TYPE)

message(STATUS "Build Configuration: ${CMAKE_BUILD_TYPE}")

project(softhsm2)

# Build Modules Path
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
                      ${CMAKE_SOURCE_DIR}/modules
                      )

# Custom Modules
include(CompilerOptions)
include(GenerateExportHeader)

# Enable CTest
enable_testing()

# config.h include path
include_directories(${CMAKE_BINARY_DIR})

add_subdirectory(src)

# Packaging
set(CPACK_PACKAGE_NAME ${PACKAGE_NAME})
set(CPACK_PACKAGE_VENDOR "OpenDNSSEC")
set(CPACK_PACKAGE_VERSION_MAJOR ${VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${VERSION_PATCH})
set(CPACK_GENERATOR "TGZ")
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_IGNORE_FILES "build/*;\.git/*")

include(CPack)
