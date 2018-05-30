project(datamgrtest)

set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/..
                 ${PROJECT_SOURCE_DIR}/../..
                 ${PROJECT_SOURCE_DIR}/../../common
                 ${PROJECT_SOURCE_DIR}/../../crypto
                 ${PROJECT_SOURCE_DIR}/../../object_store
                 ${PROJECT_SOURCE_DIR}/../../pkcs11
                 ${PROJECT_SOURCE_DIR}/../../session_mgr
                 ${PROJECT_SOURCE_DIR}/../../slot_mgr
                 ${CPPUNIT_INCLUDES}
                 ${CRYPTO_INCLUDES}
                 )

set(SOURCES datamgrtest.cpp
            ByteStringTests.cpp
            RFC4880Tests.cpp
            SecureDataMgrTests.cpp
            )

include_directories(${INCLUDE_DIRS})

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} softhsm2-static ${CRYPTO_LIBS} ${CPPUNIT_LIBS})

add_test(${PROJECT_NAME} ${PROJECT_NAME})
