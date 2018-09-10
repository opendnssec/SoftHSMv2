project(softhsm2-dump)

set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/../../lib
                 ${PROJECT_SOURCE_DIR}/../../lib/object_store
                 ${PROJECT_SOURCE_DIR}/../../lib/pkcs11
                 ${SQLITE3_INCLUDES}
                 )

set(INSTALL_TARGETS ${PROJECT_NAME}-file)
set(INSTALL_MAN_FILES ${PROJECT_NAME}-file.1)

include_directories(${INCLUDE_DIRS})

add_executable(${PROJECT_NAME}-file softhsm2-dump-file.cpp)

if(WITH_OBJECTSTORE_BACKEND_DB)
    add_executable(${PROJECT_NAME}-db softhsm2-dump-db.cpp)
    target_link_libraries(${PROJECT_NAME}-db ${SQLITE3_LIBS} ${YIELD_LIB})
    list(APPEND INSTALL_TARGETS ${PROJECT_NAME}-db)
    list(APPEND INSTALL_MAN_FILES ${PROJECT_NAME}-db.1)
endif(WITH_OBJECTSTORE_BACKEND_DB)

install(TARGETS ${INSTALL_TARGETS}
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        )

install(FILES ${INSTALL_MAN_FILES}
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
        )

