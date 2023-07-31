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

if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    list(APPEND INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/../win32)
ENDIF()

include_directories(${INCLUDE_DIRS})
add_library(${PROJECT_NAME} OBJECT ${SOURCES})
target_compile_options(${PROJECT_NAME} PRIVATE ${COMPILE_OPTIONS})

if(BUILD_TESTS)
    add_subdirectory(test)
endif(BUILD_TESTS)
