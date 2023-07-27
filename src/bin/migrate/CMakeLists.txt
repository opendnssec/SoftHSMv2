project(softhsm2-migrate)

if(BUILD_MIGRATE)
    set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/../../lib/pkcs11
                     ${PROJECT_SOURCE_DIR}/../common
                     ${SQLITE3_INCLUDES}
                     )

    set(SOURCES softhsm2-migrate.cpp
                ${PROJECT_SOURCE_DIR}/../common/findslot.cpp
                ${PROJECT_SOURCE_DIR}/../common/getpw.cpp
                ${PROJECT_SOURCE_DIR}/../common/library.cpp
                )

    if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        list(APPEND INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/../../lib/win32 ${CMAKE_CURRENT_SOURCE_DIR}/../win32)
        list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../win32/getopt.cpp)
    endif()

    include_directories(${INCLUDE_DIRS})
    add_executable(${PROJECT_NAME} ${SOURCES})
    target_link_libraries(${PROJECT_NAME} ${SQLITE3_LIBS} ${YIELD_LIB} ${CMAKE_DL_LIBS})
    target_compile_options(${PROJECT_NAME} PRIVATE ${COMPILE_OPTIONS})

    install(TARGETS ${PROJECT_NAME}
            DESTINATION ${CMAKE_INSTALL_BINDIR}
            )

    install(FILES ${PROJECT_NAME}.1
            DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
            )
endif(BUILD_MIGRATE)
