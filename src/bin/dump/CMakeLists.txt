project(softhsm2-dump)

set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/../../lib
                 ${PROJECT_SOURCE_DIR}/../../lib/object_store
                 ${PROJECT_SOURCE_DIR}/../../lib/pkcs11
                 ${SQLITE3_INCLUDES}
                 )

include_directories(${INCLUDE_DIRS})

add_executable(${PROJECT_NAME}-file softhsm2-dump-file.cpp)

if(WITH_OBJECTSTORE_BACKEND_DB)
    add_executable(${PROJECT_NAME}-db softhsm2-dump-db.cpp)
    target_link_libraries(${PROJECT_NAME}-db ${SQLITE3_LIBS} ${YIELD_LIB})
endif(WITH_OBJECTSTORE_BACKEND_DB)
