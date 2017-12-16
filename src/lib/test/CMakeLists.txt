project(p11test)

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

include_directories(${PROJECT_SOURCE_DIR})

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} softhsm2-static ${CRYPTO_LIBS} ${CPPUNIT_LIBS})
set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS -pthread)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME}
         WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
         )
