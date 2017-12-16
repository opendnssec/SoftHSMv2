cmake_minimum_required(VERSION 3.5)

project(softhsm2)

# Build Options
option(BUILD_TESTS "Compile tests along with libraries" OFF)
option(WITH_BOTAN "Compile with support of BOTAN" OFF)
option(WITH_OPENSSL "Compile with support of OpenSSL" ON)

# Build Modules Path
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
                      ${CMAKE_SOURCE_DIR}/modules
                      )
include(GenerateExportHeader)

# Enable C++11 support & options
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

# Position Independent Code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Compiler Options/Macros
add_definitions(-DHAVE_CONFIG_H)
add_definitions(-DPIC)

add_compile_options(-Wall)
add_compile_options(-Wextra)

# Find OpenSSL Crypto Backend
if(WITH_OPENSSL)
    include(FindOpenSSL)
    if(OPENSSL_FOUND)
        message(STATUS "Found OpenSSL: ${OPENSSL_VERSION}")
        set(CRYPTO_INCLUDES ${OPENSSL_INCLUDE_DIR})
        set(CRYPTO_LIBS ${OPENSSL_LIBRARIES})
    else(OPENSSL_FOUND)
        message(FATAL_ERROR "Failed to find OpenSSL!")
    endif(OPENSSL_FOUND)
endif(WITH_OPENSSL)

# Find Botan
if(WITH_BOTAN)
    include(FindBotan)
    if(BOTAN_FOUND)
        message(STATUS "Found Botan")
    else(BOTAN_FOUND)
        message(FATAL_ERROR "Failed to find Botan!")
    endif(BOTAN_FOUND)
endif(WITH_BOTAN)

if(BUILD_TESTS)
    include(FindCppUnit)
    if(CPPUNIT_FOUND)
        message(STATUS "Found CppUnit")
        set(CPPUNIT_INCLUDES ${CPPUNIT_INCLUDE_DIR})
        set(CPPUNIT_LIBS ${CPPUNIT_LIBRARY})
    else(CPPUNIT_FOUND)
        message(FATAL_ERROR "Failed to find CppUnit!")
    endif(CPPUNIT_FOUND)
endif(BUILD_TESTS)

# Enable CTest
enable_testing()

add_subdirectory(src)
