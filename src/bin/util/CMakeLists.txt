project(softhsm2-util)

set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/../common
                 ${PROJECT_SOURCE_DIR}/../../lib/common
                 ${PROJECT_SOURCE_DIR}/../../lib/crypto
                 ${PROJECT_SOURCE_DIR}/../../lib/data_mgr
                 ${PROJECT_SOURCE_DIR}/../../lib/object_store
                 ${PROJECT_SOURCE_DIR}/../../lib/pkcs11
                 ${CRYPTO_INCLUDES}
                 ${SQLITE3_INCLUDES}
                 )

set(SOURCES softhsm2-util.cpp
            ${PROJECT_SOURCE_DIR}/../common/findslot.cpp
            ${PROJECT_SOURCE_DIR}/../common/getpw.cpp
            ${PROJECT_SOURCE_DIR}/../common/library.cpp
            )

if(WITH_OPENSSL)
    list(APPEND SOURCES softhsm2-util-ossl.cpp
                        ${PROJECT_SOURCE_DIR}/../../lib/crypto/OSSLComp.cpp
                        )
endif(WITH_OPENSSL)

if(WITH_BOTAN)
    list(APPEND SOURCES softhsm2-util-botan.cpp)
endif(WITH_BOTAN)

if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    list(APPEND INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/../../lib/win32 ${CMAKE_CURRENT_SOURCE_DIR}/../win32)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../win32/getopt.cpp)
endif()

include_directories(${INCLUDE_DIRS})
add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} softhsm2-static ${CRYPTO_LIBS} ${SQLITE3_LIBS} ${CMAKE_DL_LIBS})
target_compile_options(${PROJECT_NAME} PRIVATE ${COMPILE_OPTIONS})

install(TARGETS ${PROJECT_NAME}
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        )

install(FILES ${PROJECT_NAME}.1
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
        )
