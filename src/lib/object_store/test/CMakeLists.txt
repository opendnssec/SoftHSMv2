project(objstoretest)

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

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} softhsm2-static ${CRYPTO_LIBS} ${CPPUNIT_LIBS} ${SQLITE3_LIBS})

add_test(${PROJECT_NAME} ${PROJECT_NAME})
