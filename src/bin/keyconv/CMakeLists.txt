project(softhsm2-keyconv)

set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/../../lib/crypto
                 ${CRYPTO_INCLUDES}
                 )

set(SOURCES softhsm2-keyconv.cpp
            base64.c
            )

if(WITH_OPENSSL)
    list(APPEND SOURCES softhsm2-keyconv-ossl.cpp
                        ${PROJECT_SOURCE_DIR}/../../lib/crypto/OSSLComp.cpp
                        )
endif(WITH_OPENSSL)

if(WITH_BOTAN)
    list(APPEND SOURCES softhsm2-keyconv-botan.cpp)
endif(WITH_BOTAN)

include_directories(${INCLUDE_DIRS})
add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${CRYPTO_LIBS})

install(TARGETS ${PROJECT_NAME}
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        )

install(FILES ${PROJECT_NAME}.1
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
        )
