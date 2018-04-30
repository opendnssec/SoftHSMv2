project(p11test)

set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}
                 ${PROJECT_SOURCE_DIR}/..
                 ${PROJECT_SOURCE_DIR}/../common
                 ${PROJECT_SOURCE_DIR}/../pkcs11
                 ${CPPUNIT_INCLUDES}
                 )

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

include_directories(${INCLUDE_DIRS})

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} softhsm2-static ${CRYPTO_LIBS} ${CPPUNIT_LIBS} ${SQLITE3_LIBS})
set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS -pthread)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME}
         WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
         )

set(builddir ${PROJECT_BINARY_DIR})
configure_file(softhsm2.conf.in softhsm2.conf)
configure_file(softhsm2-alt.conf.in softhsm2-alt.conf)
configure_file(tokens/dummy.in tokens/dummy)
