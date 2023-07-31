project(p11test)

set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}
                 ${PROJECT_SOURCE_DIR}/..
                 ${PROJECT_SOURCE_DIR}/../common
                 ${PROJECT_SOURCE_DIR}/../pkcs11
                 ${CPPUNIT_INCLUDES}
                 )
if (WIN32)
    set(INCLUDE_DIRS ${INCLUDE_DIRS} ${PROJECT_SOURCE_DIR}/../win32)
endif (WIN32)

set(SOURCES p11test.cpp
            SymmetricAlgorithmTests.cpp
            DigestTests.cpp
            InitTests.cpp
            InfoTests.cpp
            RandomTests.cpp
            SessionTests.cpp
            TokenTests.cpp
            UserTests.cpp
            ObjectTests.cpp
            DeriveTests.cpp
            SignVerifyTests.cpp
            AsymEncryptDecryptTests.cpp
            AsymWrapUnwrapTests.cpp
            TestsBase.cpp
            TestsNoPINInitBase.cpp
            ../common/log.cpp
            ../common/osmutex.cpp
            )
add_executable(${PROJECT_NAME} ${SOURCES})
			
if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    list(APPEND SOURCES ${PROJECT_SOURCE_DIR}/../win32/setenv.cpp ${PROJECT_SOURCE_DIR}/../win32/syslog.cpp)
    list(APPEND COMPILE_OPTIONS "/DCRYPTOKI_STATIC")
else()
    list(APPEND SOURCES "ForkTests.cpp")
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS -pthread)
endif()

include_directories(${INCLUDE_DIRS})


target_link_libraries(${PROJECT_NAME} softhsm2-static ${SQLITE3_LIBS} ${CPPUNIT_LIBRARIES})
set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS -pthread)

target_compile_options(${PROJECT_NAME} PRIVATE ${COMPILE_OPTIONS})

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME}
         WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
         )

set(builddir ${PROJECT_BINARY_DIR})
configure_file(softhsm2.conf.in softhsm2.conf)
configure_file(softhsm2-alt.conf.in softhsm2-alt.conf)
configure_file(softhsm2-reset-on-fork.conf.in softhsm2-reset-on-fork.conf)
configure_file(softhsm2-negative-mech.conf.in softhsm2-negative-mech.conf)
configure_file(softhsm2-mech.conf.in softhsm2-mech.conf)
configure_file(tokens/dummy.in tokens/dummy)
