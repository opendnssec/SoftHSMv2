project(softhsm_datamgr)

set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}
                 ${PROJECT_SOURCE_DIR}/../crypto
                 ${PROJECT_SOURCE_DIR}/../common
                 ${PROJECT_SOURCE_DIR}/../pkcs11
                 )
if (WIN32)
    set(INCLUDE_DIRS ${INCLUDE_DIRS} ${PROJECT_SOURCE_DIR}/../win32)
endif (WIN32)

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
