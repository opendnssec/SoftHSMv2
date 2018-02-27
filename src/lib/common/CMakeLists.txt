project(softhsm_common)

set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}
                 ${PROJECT_SOURCE_DIR}/../crypto
                 ${PROJECT_SOURCE_DIR}/../data_mgr
                 ${PROJECT_SOURCE_DIR}/../pkcs11
                 )

set(SOURCES Configuration.cpp
            fatal.cpp
            log.cpp
            MutexFactory.cpp
            osmutex.cpp
            SimpleConfigLoader.cpp
            )

include_directories(${INCLUDE_DIRS})

add_library(${PROJECT_NAME}-obj OBJECT ${SOURCES})
add_library(${PROJECT_NAME} STATIC $<TARGET_OBJECTS:${PROJECT_NAME}-obj>)

configure_file(softhsm2.conf.in ${PROJECT_BINARY_DIR}/softhsm2.conf)
configure_file(softhsm2.conf.5.in ${PROJECT_BINARY_DIR}/softhsm2.conf.5)

