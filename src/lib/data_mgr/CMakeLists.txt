project(softhsm_datamgr)

set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}
                 ${PROJECT_SOURCE_DIR}/../crypto
                 ${PROJECT_SOURCE_DIR}/../common
                 ${PROJECT_SOURCE_DIR}/../pkcs11
                 )

set(SOURCES ByteString.cpp
            RFC4880.cpp
            salloc.cpp
            SecureDataManager.cpp
            SecureMemoryRegistry.cpp
            )

include_directories(${INCLUDE_DIRS})

add_library(${PROJECT_NAME}-obj OBJECT ${SOURCES})
add_library(${PROJECT_NAME} STATIC $<TARGET_OBJECTS:${PROJECT_NAME}-obj>)

if(BUILD_TESTS)
    add_subdirectory(test)
endif(BUILD_TESTS)
