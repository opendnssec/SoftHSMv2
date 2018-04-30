project(objstoretest)

set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/..
                 ${PROJECT_SOURCE_DIR}/../..
                 ${PROJECT_SOURCE_DIR}/../../common
                 ${PROJECT_SOURCE_DIR}/../../crypto
                 ${PROJECT_SOURCE_DIR}/../../data_mgr
                 ${PROJECT_SOURCE_DIR}/../../pkcs11
                 ${PROJECT_SOURCE_DIR}/../../session_mgr
                 ${PROJECT_SOURCE_DIR}/../../slot_mgr
                 ${CPPUNIT_INCLUDES}
                 ${CRYPTO_INCLUDES}
                 )

set(SOURCES objstoretest.cpp
            DirectoryTests.cpp
            UUIDTests.cpp
            FileTests.cpp
            ObjectFileTests.cpp
            OSTokenTests.cpp
            ObjectStoreTests.cpp
            SessionObjectTests.cpp
            SessionObjectStoreTests.cpp
            )

if(WITH_OBJECTSTORE_BACKEND_DB)
    list(APPEND SOURCES DBTests.cpp
                        DBObjectTests.cpp
                        DBTokenTests.cpp
                        DBObjectStoreTests.cpp
                        )
endif(WITH_OBJECTSTORE_BACKEND_DB)

include_directories(${INCLUDE_DIRS})

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} softhsm2-static ${CRYPTO_LIBS} ${CPPUNIT_LIBS} ${SQLITE3_LIBS})

add_test(${PROJECT_NAME} ${PROJECT_NAME})
