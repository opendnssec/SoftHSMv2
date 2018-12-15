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

add_library(${PROJECT_NAME} OBJECT ${SOURCES})

if(BUILD_TESTS)
    add_subdirectory(test)
endif(BUILD_TESTS)
