include(CheckIncludeFiles)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckLibraryExists)
include(CheckTypeSize)

# Configures C++11# Enable C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable Position Independent Code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_definitions(-DPIC)

# Compiler Options/Macros
add_compile_options(-Wall)
add_compile_options(-Wextra)

# Equivalent of acx_64bit.m4
if(ENABLE_64BIT)
    if(CMAKE_SIZEOF_VOID_P STREQUAL "8")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m64")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m64")
    else(CMAKE_SIZEOF_VOID_P STREQUAL "8")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")
    endif(CMAKE_SIZEOF_VOID_P STREQUAL "8")
endif(ENABLE_64BIT)

# Equivalent of acx_visibility.m4
if(DISABLE_VISIBILITY)
    message(STATUS "-fvisibility=hidden has been disabled")
else(DISABLE_VISIBILITY)
    set(CRYPTOKI_VISIBILITY 1)
    set(CMAKE_CXX_VISIBILITY_PRESET hidden)
endif(DISABLE_VISIBILITY)

#[[
# acx_non_paged_memory.m4
if(DISABLE_NON_PAGED_MEMORY)
    message(STATUS "non-paged-memoery disabled")
else(DISABLE_NON_PAGED_MEMORY)
    set(SENSITIVE_NON_PAGE 1)
    check_include_files(sys/mman.h HAVE_SYS_MMAN_H)
    execute_process(COMMAND ulimit -l OUTPUT_VARIABLE MLOCK_SIZE)
    if(MLOCK_SIZE NOT STREQUAL "unlimited")
        message(WARNING "
======================================================================
SoftHSM has been configured to store sensitive data in non-page RAM
(i.e. memory that is not swapped out to disk). This is the default and
most secure configuration. Your system, however, is not configured to
support this model in non-privileged accounts (i.e. user accounts).

You can check the setting on your system by running the following
command in a shell:

        ulimit -l

If this does not return \"unlimited\" and you plan to run SoftHSM from
non-privileged accounts then you should edit the configuration file
/etc/security/limits.conf (on most systems).

You will need to add the following lines to this file:

#<domain>       <type>          <item>          <value>
*               -               memlock         unlimited

Alternatively, you can elect to disable this feature of SoftHSM by
re-running configure with the option \"--disable-non-paged-memory\". 
Please be advised that this may seriously degrade the security of 
SoftHSM.
======================================================================
        ")
    endif(MLOCK_SIZE NOT STREQUAL "unlimited")
endif(DISABLE_NON_PAGED_MEMORY)

# Check if -ldl exists (equivalent of acx_dlopen.m4)
check_library_exists(dl dlopen "" HAVE_DLOPEN)
check_function_exists(LoadLibrary HAVE_LOADLIBRARY)

]]
# Find Botan Crypto Backend (equivalent of acx_botan.m4)
if(WITH_BOTAN)
    include(FindBotan)
    if(BOTAN_FOUND)
        message(STATUS "Found Botan")
    else(BOTAN_FOUND)
        message(FATAL_ERROR "Failed to find Botan!")
    endif(BOTAN_FOUND)
endif(WITH_BOTAN)

# Find OpenSSL Crypto Backend (equivalent of acx_crypto_backend.m4)
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

# Find SQLite3
if(WITH_SQLITE3)
    include(FindSQLite3)
    if(SQLITE3_FOUND)
        message(STATUS "Found SQLite3")
        set(SQLITE3_INCLUDES ${SQLITE3_INCLUDE_DIRS})
        set(SQLITE3_LIBS ${SQLITE3_LIBRARIES})
    else(SQLITE3_FOUND)
        message(FATAL_ERROR "Failed to find SQLite3!")
    endif(SQLITE3_FOUND)
endif(WITH_SQLITE3)

if(BUILD_TESTS)
    # Find CppUnit (equivalent of acx_cppunit.m4)
    include(FindCppUnit)
    if(CPPUNIT_FOUND)
        message(STATUS "Found CppUnit")
        set(CPPUNIT_INCLUDES ${CPPUNIT_INCLUDE_DIR})
        set(CPPUNIT_LIBS ${CPPUNIT_LIBRARY})
    else(CPPUNIT_FOUND)
        message(FATAL_ERROR "Failed to find CppUnit!")
    endif(CPPUNIT_FOUND)
endif(BUILD_TESTS)

#[[
configure_file(config.h.in.cmake ${CMAKE_BINARY_DIR}/config.h)
]]
