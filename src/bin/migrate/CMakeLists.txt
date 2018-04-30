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

    include_directories(${INCLUDE_DIRS})
    add_executable(${PROJECT_NAME} ${SOURCES})
    target_link_libraries(${PROJECT_NAME} ${SQLITE3_LIBS} ${YIELD_LIB} ${CMAKE_DL_LIBS})

    install(TARGETS ${PROJECT_NAME}
            DESTINATION ${CMAKE_INSTALL_BINDIR}
            )

    install(FILES ${PROJECT_NAME}.1
            DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
            )
endif(BUILD_MIGRATE)
