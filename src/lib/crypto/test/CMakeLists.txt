project(cryptotest)

set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/..
                 ${PROJECT_SOURCE_DIR}/../..
                 ${PROJECT_SOURCE_DIR}/../../common
                 ${PROJECT_SOURCE_DIR}/../../data_mgr
                 ${PROJECT_SOURCE_DIR}/../../object_store
                 ${PROJECT_SOURCE_DIR}/../../pkcs11
                 ${PROJECT_SOURCE_DIR}/../../session_mgr
                 ${PROJECT_SOURCE_DIR}/../../slot_mgr
                 ${CPPUNIT_INCLUDES}
                 ${CRYPTO_INCLUDES}
                 )

set(SOURCES cryptotest.cpp
            AESTests.cpp
            DESTests.cpp
            DHTests.cpp
            DSATests.cpp
            ECDHTests.cpp
            ECDSATests.cpp
            EDDSATests.cpp
            GOSTTests.cpp
            HashTests.cpp
            MacTests.cpp
            RNGTests.cpp
            RSATests.cpp
            chisq.c
            ent.c
            iso8859.c
            randtest.c
            )

include_directories(${INCLUDE_DIRS})

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} softhsm2-static ${CRYPTO_LIBS} ${CPPUNIT_LIBS})

add_test(${PROJECT_NAME} ${PROJECT_NAME})
