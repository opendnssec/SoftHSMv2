include(CheckCXXCompilerFlag)
include(CheckFunctionExists)
include(CheckIncludeFiles)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckTypeSize)

function(enable_cxx_compiler_flag_if_supported flag)
    string(FIND "${CMAKE_CXX_FLAGS}" "${flag}" flag_already_set)
    if(flag_already_set EQUAL -1)
        check_cxx_compiler_flag("${flag}" flag_supported)
        if(flag_supported)
            add_compile_options(${flag})
        elseif(flag_supported)
            message(WARNING "unsupported compiler flag: ${flag}")
        endif(flag_supported)
        unset(flag_supported CACHE)
    endif()
endfunction()

# Configures C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(HAVE_CXX11 ON)

if(ENABLE_PEDANTIC)
    enable_cxx_compiler_flag_if_supported(-pedantic)
    set(ENABLE_STRICT ON)
endif(ENABLE_PEDANTIC)

if(ENABLE_STRICT)
    set(CMAKE_CXX_EXTENSIONS OFF)
endif(ENABLE_STRICT)

if(ENABLE_SHARED)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif(ENABLE_SHARED)

# Compiler Options/Macros
check_symbol_exists(STDC_HEADERS "c++config.h" STDC_HEADERS)

# acx_strict.m4
if(ENABLE_STRICT)
    enable_cxx_compiler_flag_if_supported(-Wall)
    enable_cxx_compiler_flag_if_supported(-Wextra)
endif(ENABLE_STRICT)

# acx_64bit.m4
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

# acx_non_paged_memory.m4
if(DISABLE_NON_PAGED_MEMORY)
    message(STATUS "non-paged-memory disabled")
else(DISABLE_NON_PAGED_MEMORY)
    set(SENSITIVE_NON_PAGE ON)
    check_include_files(sys/mman.h HAVE_SYS_MMAN_H)
    execute_process(COMMAND bash -c "ulimit -l"
                    OUTPUT_VARIABLE MLOCK_SIZE
                    OUTPUT_STRIP_TRAILING_WHITESPACE
                    )
    if(NOT "${MLOCK_SIZE}" STREQUAL "unlimited")
        message(WARNING "\
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
    ======================================================================")
    endif(NOT "${MLOCK_SIZE}" STREQUAL "unlimited")
endif(DISABLE_NON_PAGED_MEMORY)

# Check if -ldl exists (equivalent of acx_dlopen.m4)
check_library_exists(dl dlopen "" HAVE_DLOPEN)
check_function_exists(LoadLibrary HAVE_LOADLIBRARY)

# Find Botan Crypto Backend (equivalent of acx_botan.m4)
if(WITH_BOTAN)
    include(FindBotan)
    if(BOTAN_FOUND)
        message(STATUS "Found Botan")
        set(CRYPTO_INCLUDES ${BOTAN_INCLUDE_DIRS})
        set(CRYPTO_LIBS ${BOTAN_LIBRARIES})
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
        set(WITH_RAW_PSS 1)
        set(WITH_AES_GCM 1)

        # acx_openssl_ecc.m4
        set(testfile ${CMAKE_SOURCE_DIR}/modules/tests/test_openssl_ecc.c)
        try_run(RUN_ECC COMPILE_RESULT
                "${CMAKE_BINARY_DIR}/prebuild_santity_tests" ${testfile}
                LINK_LIBRARIES ${CRYPTO_LIBS}
                CMAKE_FLAGS
                    "-DINCLUDE_DIRECTORIES=${CRYPTO_INCLUDES}"
                )
        if(NOT COMPILE_RESULT)
            message(FATAL_ERROR "failed to compile: ${testfile}")
        endif(NOT COMPILE_RESULT)

        if(RUN_ECC EQUAL 0)
            message(STATUS "OpenSSL: found P-256, P-384, and P-521")
        else()
            set(error_msg "OpenSSL: cannot find P-256, P-384, or P-521! OpenSSL library has no ECC support!")
            if(ENABLE_ECC)
                message(FATAL_ERROR ${error_msg})
            else(ENABLE_ECC)
                message(WARNING ${error_msg})
            endif(ENABLE_ECC)
        endif()

        # acx_openssl_gost.m4
        set(testfile ${CMAKE_SOURCE_DIR}/modules/tests/test_openssl_gost.c)
        try_run(RUN_GOST COMPILE_RESULT
                "${CMAKE_BINARY_DIR}/prebuild_santity_tests" ${testfile}
                LINK_LIBRARIES ${CRYPTO_LIBS}
                CMAKE_FLAGS
                    "-DINCLUDE_DIRECTORIES=${CRYPTO_INCLUDES}"
                )
        if(NOT COMPILE_RESULT)
            message(FATAL_ERROR "failed to compile: ${testfile}")
        endif(NOT COMPILE_RESULT)

        if(RUN_GOST EQUAL 0)
            message(STATUS "OpenSSL: found GOST engine")
        else()
            set(error_msg "OpenSSL: cannot find GOST engine! OpenSSL library has no GOST support!")
            if(ENABLE_GOST)
                message(FATAL_ERROR ${error_msg})
            else(ENABLE_GOST)
                message(WARNING ${error_msg})
            endif(ENABLE_GOST)
        endif()

        # acx_openssl_fips.m4
        set(testfile ${CMAKE_SOURCE_DIR}/modules/tests/test_openssl_fips.c)
        try_run(RUN_FIPS COMPILE_RESULT
                "${CMAKE_BINARY_DIR}/prebuild_santity_tests" ${testfile}
                LINK_LIBRARIES ${CRYPTO_LIBS}
                CMAKE_FLAGS
                    "-DINCLUDE_DIRECTORIES=${CRYPTO_INCLUDES}"
                )
        if(NOT COMPILE_RESULT)
            message(FATAL_ERROR "failed to compile: ${testfile}")
        endif(NOT COMPILE_RESULT)

        if(RUN_FIPS EQUAL 0)
            message(STATUS "OpenSSL: found working FIPS_mode_set()")
        else()
            set(error_msg "OpenSSL: FIPS_mode_set(1) failed. OpenSSL library is not FIPS capable!")
            if(ENABLE_FIPS)
                message(FATAL_ERROR ${error_msg})
            else(ENABLE_FIPS)
                message(WARNING ${error_msg})
            endif(ENABLE_FIPS)
        endif()

        # acx_openssl_rfc3349
        # acx_openssl_rfc5649

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

configure_file(config.h.in.cmake ${CMAKE_BINARY_DIR}/config.h)
