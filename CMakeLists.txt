cmake_minimum_required(VERSION 3.5)

project(softhsm2 C CXX)

# Build Options
option(BUILD_TESTS "Compile tests along with libraries" OFF)
option(DISABLE_NON_PAGED_MEMORY "Disable non-paged memory for secure storage" OFF)
option(DISABLE_VISIBILITY "Disables and unsets -fvisibility=hidden" OFF)
option(ENABLE_64bit "Enable 64-bit compiling" OFF)
option(ENABLE_ECC "Enable support for ECC" ON)
option(ENABLE_EDDSA "Enable support for EDDSA" OFF)
option(ENABLE_GOST "Enable support for GOST" ON)
option(ENABLE_FIPS "Enable support for FIPS 140-2 mode" OFF)
option(ENABLE_P11_KIT "Enable p11-kit integration" ON)
option(ENABLE_PEDANTIC "Enable pedantic compile mode" OFF)
option(ENABLE_STRICT "Enable strict compile mode" ON)
option(ENABLE_SHARED "Build shared libraries" ON)
option(ENABLE_STATIC "Build static libraries" ON)
option(WITH_OBJECTSTORE_BACKEND_DB "Build with object store backend database (SQLite3)" OFF)
option(WITH_MIGRATE "Build migration tool. Requires SQLite3." OFF)
set(WITH_CRYPTO_BACKEND "openssl"
    CACHE STRING "Select crypto backend (openssl|botan)")
set(WITH_P11_KIT ""
    CACHE STRING "Specify install path of the p11-kit module, will override path given by pkg-config")

if(WITH_OBJECTSTORE_BACKEND_DB)
    set(HAVE_OBJECTSTORE_BACKEND_DB 1)
    set(WITH_MIGRATE ON)
    set(WITH_SQLITE3 ON)
    message(STATUS "Building with support for object store backend database")
else(WITH_OBJECTSTORE_BACKEND_DB)
    message(STATUS "Building with no support for object store backend database")
endif(WITH_OBJECTSTORE_BACKEND_DB)

if(WITH_MIGRATE)
    set(BUILD_MIGRATE ON)
    set(WITH_SQLITE3 ON)
    message(STATUS "Building with migration tool")
else(WITH_MIGRATE)
    message(STATUS "Building with no migration tool")
endif(WITH_MIGRATE)

if(NOT DEFINED CMAKE_INSTALL_SYSCONFDIR)
    set(CMAKE_INSTALL_SYSCONFDIR "/etc")
endif()
if(NOT DEFINED CMAKE_INSTALL_LOCALSTATEDIR)
    set(CMAKE_INSTALL_LOCALSTATEDIR "/var")
endif()
include(GNUInstallDirs)

set(DEFAULT_LOG_LEVEL "INFO"
    CACHE STRING "The default log level")
set(DEFAULT_OBJECTSTORE_BACKEND "file"
    CACHE STRING "Default storage backend for token objects")
set(DEFAULT_PKCS11_LIB "${CMAKE_INSTALL_FULL_LIBDIR}/softhsm/libsofthsm2.so"
    CACHE STRING "The default PKCS#11 library")
set(DEFAULT_SOFTHSM2_CONF "${CMAKE_INSTALL_FULL_SYSCONFDIR}/softhsm2.conf"
    CACHE STRING "The default location of softhsm.conf")
set(DEFAULT_TOKENDIR "${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/lib/softhsm/tokens/"
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

# p11-kit
set(default_softhsm2_lib ${DEFAULT_PKCS11_LIB})
configure_file(softhsm2.module.in softhsm2.module)
if(ENABLE_P11_KIT)
    install(FILES ${PROJECT_BINARY_DIR}/softhsm2.module
            DESTINATION ${P11KIT_PATH}
            )
endif(ENABLE_P11_KIT)

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
