project(softhsm_sessionmgr)

set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}
                 ${PROJECT_SOURCE_DIR}/../common
                 ${PROJECT_SOURCE_DIR}/../crypto
                 ${PROJECT_SOURCE_DIR}/../data_mgr
                 ${PROJECT_SOURCE_DIR}/../object_store
                 ${PROJECT_SOURCE_DIR}/../pkcs11
                 ${PROJECT_SOURCE_DIR}/../slot_mgr
                 )

set(SOURCES SessionManager.cpp
            Session.cpp
            )

include_directories(${INCLUDE_DIRS})

add_library(${PROJECT_NAME}-obj OBJECT ${SOURCES})
add_library(${PROJECT_NAME} STATIC $<TARGET_OBJECTS:${PROJECT_NAME}-obj>)

if(BUILD_TESTS)
    add_subdirectory(test)
endif(BUILD_TESTS)
