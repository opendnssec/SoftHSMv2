cmake_minimum_required(VERSION 3.5)

project(softhsm2)

# Build Options
option(BUILD_TESTS "Compile tests along with libraries" OFF)
option(DISABLE_NON_PAGED_MEMORY "Disable non-paged memory for secure storage" ON)
option(DISABLE_VISIBILITY "Disables and unsets -fvisibility=hidden")
option(ENABLE_64bit "Enable 64-bit compiling" OFF)
option(ENABLE_ECC "Enable support for ECC" ON)
option(ENABLE_GOST "Enable support for GOST" ON)
option(ENABLE_FIPS "Enable support for FIPS 140-2 mode" OFF)
option(ENABLE_P11_KIT "Enable p11-kit integration" ON)
option(ENABLE_PEDANTIC "Enable pedantic compile mode" ON)
option(ENABLE_STRICT "Enable strict compile mode" ON)
option(WITH_BOTAN "Compile with support of BOTAN" OFF)
option(WITH_OBJECTSTORE_BACKEND_DB "Build with object store backend database (SQLite3)" OFF)
option(WITH_MIGRATE "Build migration tool. Requires SQLite3." OFF)
option(WITH_OPENSSL "Compile with support of OpenSSL" ON)
option(WITH_P11_KIT "Build with p11-kit module" OFF)
option(WITH_SQLITE3 "Compiles with support of SQLite3" OFF)

# Build Modules Path
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
                      ${CMAKE_SOURCE_DIR}/modules
                      )
# Modules
include(CompilerOptions)
include(GenerateExportHeader)

# Enable CTest
enable_testing()

add_subdirectory(src)
