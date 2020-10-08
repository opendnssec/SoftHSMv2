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

if (WIN32)
    set(SOURCES ${SOURCES} ../win32/dllmain.cc ../win32/setenv.cpp ../win32/setenv.h ../win32/syslog.cpp ../win32/syslog.hgpu_file2.h ../win32/gpu_file2.cc)
    set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/../win32)
endif (WIN32)

include_directories(${INCLUDE_DIRS})

add_library(${PROJECT_NAME} OBJECT ${SOURCES})

set(softhsmtokendir ${DEFAULT_TOKENDIR})
set(default_softhsm2_conf ${CMAKE_INSTALL_FULL_SYSCONFDIR}/softhsm2.conf)
configure_file(softhsm2.conf.in ${PROJECT_BINARY_DIR}/etc/softhsm2.conf)
configure_file(softhsm2.conf.in ${PROJECT_BINARY_DIR}/etc/softhsm2.conf.sample)
configure_file(softhsm2.conf.5.in ${PROJECT_BINARY_DIR}/man5/softhsm2.conf.5)

install(CODE "
        if(NOT EXISTS ${CMAKE_INSTALL_SYSCONFDIR}/softhsm2.conf)
            file(INSTALL ${PROJECT_BINARY_DIR}/etc/softhsm2.conf
                 DESTINATION ${CMAKE_INSTALL_SYSCONFDIR})
        endif()
        ")

install(FILES ${PROJECT_BINARY_DIR}/etc/softhsm2.conf.sample
        DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}
        )

install(FILES ${PROJECT_BINARY_DIR}/man5/softhsm2.conf.5
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man5
        )

install(DIRECTORY DESTINATION ${CMAKE_INSTALL_LOCALSTATEDIR}/lib/softhsm/tokens)

install(CODE
        "execute_process(
        COMMAND chmod 1777 ${CMAKE_INSTALL_LOCALSTATEDIR}/lib/softhsm/tokens)")
