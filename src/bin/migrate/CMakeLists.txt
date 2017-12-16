project(softhsm2-migrate)

if(WITH_SQLITE3)
    set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/../../lib/pkcs11
                     ${PROJECT_SOURCE_DIR}/../common
                     ${SQLITE3_INCLUDES}
                     ${CMAKE_SOURCE_DIR}
                     )

    set(SOURCES softhsm2-migrate.cpp
                ${PROJECT_SOURCE_DIR}/../common/findslot.cpp
                ${PROJECT_SOURCE_DIR}/../common/getpw.cpp
                ${PROJECT_SOURCE_DIR}/../common/library.cpp
                )

    include_directories(${INCLUDE_DIRS})
    add_executable(${PROJECT_NAME} ${SOURCES})
    target_link_libraries(${PROJECT_NAME} ${SQLITE3_LIBS} ${YIELD_LIB})
endif(WITH_SQLITE3)
