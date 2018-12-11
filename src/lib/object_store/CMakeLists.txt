project(softhsm_objectstore)

set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}
                 ${PROJECT_SOURCE_DIR}/../common
                 ${PROJECT_SOURCE_DIR}/../crypto
                 ${PROJECT_SOURCE_DIR}/../data_mgr
                 ${PROJECT_SOURCE_DIR}/../pkcs11
                 ${SQLITE3_INCLUDES}
                 )

set(SOURCES Directory.cpp
            File.cpp
            FindOperation.cpp
            Generation.cpp
            ObjectFile.cpp
            ObjectStore.cpp
            ObjectStoreToken.cpp
            OSAttribute.cpp
            OSToken.cpp
            SessionObject.cpp
            SessionObjectStore.cpp
            UUID.cpp
            )

if(WITH_OBJECTSTORE_BACKEND_DB)
    list(APPEND SOURCES DB.cpp
                        DBObject.cpp
                        DBToken.cpp
                        )
endif(WITH_OBJECTSTORE_BACKEND_DB)


include_directories(${INCLUDE_DIRS})

add_library(${PROJECT_NAME} OBJECT ${SOURCES})
# Versions before CMake 3.12 cannot use target_link_libraries on object
# libraries, a workaround exists in src/lib/CMakeLists.txt.
if(NOT CMAKE_VERSION VERSION_LESS "3.12")
        target_link_libraries(${PROJECT_NAME} ${SQLITE3_LIBS})
endif()

if(BUILD_TESTS)
    add_subdirectory(test)
endif(BUILD_TESTS)
