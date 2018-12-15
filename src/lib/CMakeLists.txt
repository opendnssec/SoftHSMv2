###############################################################################
# Dependencies
###############################################################################
add_subdirectory(common)
add_subdirectory(crypto)
add_subdirectory(data_mgr)
add_subdirectory(handle_mgr)
add_subdirectory(object_store)
add_subdirectory(session_mgr)
add_subdirectory(slot_mgr)

###############################################################################
# SoftHSMv2 Config
###############################################################################
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/common
                 ${CMAKE_CURRENT_SOURCE_DIR}/crypto
                 ${CMAKE_CURRENT_SOURCE_DIR}/data_mgr
                 ${CMAKE_CURRENT_SOURCE_DIR}/handle_mgr
                 ${CMAKE_CURRENT_SOURCE_DIR}/object_store
                 ${CMAKE_CURRENT_SOURCE_DIR}/pkcs11
                 ${CMAKE_CURRENT_SOURCE_DIR}/session_mgr
                 ${CMAKE_CURRENT_SOURCE_DIR}/slot_mgr
                 ${CRYPTO_INCLUDES}
                 )

include_directories(${INCLUDE_DIRS})

set(SOURCES access.cpp
            main.cpp
            P11Attributes.cpp
            P11Objects.cpp
            SoftHSM.cpp
            )

set(STATIC_FILES softhsm_common
                 softhsm_crypto
                 softhsm_datamgr
                 softhsm_handlemgr
                 softhsm_objectstore
                 softhsm_sessionmgr
                 softhsm_slotmgr
                 )

if(CMAKE_VERSION VERSION_LESS "3.12")
        # Older CMake versions cannot link object libraries to a target, so pass
        # the associated object files as source. Similarly, softhsm_crypto and
        # softhsm_objectstore object library dependencies cannot be propagated
        # so as a workaround explicitly specify it here.
        foreach(libname IN LISTS STATIC_FILES)
                list(APPEND SOURCES $<TARGET_OBJECTS:${libname}>)
        endforeach()
        # Older CMake versions forbid library dependencies on object libraries,
        # therefore repeat softhsm_crypto and softhsm_objectstore dependencies.
        set(STATIC_FILES ${CRYPTO_LIBS} ${SQLITE3_LIBS})
endif()


###############################################################################
# Static Library Config
###############################################################################
add_library(${PROJECT_NAME}-static STATIC ${SOURCES})
target_link_libraries(${PROJECT_NAME}-static ${STATIC_FILES})
set_target_properties(${PROJECT_NAME}-static
                      PROPERTIES OUTPUT_NAME ${PROJECT_NAME}
                      )
generate_export_header(${PROJECT_NAME}-static)

###############################################################################
# Shared Library Config
###############################################################################
add_library(${PROJECT_NAME} SHARED ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${STATIC_FILES})
generate_export_header(${PROJECT_NAME})

###############################################################################
# Tests
###############################################################################
if(BUILD_TESTS)
    add_subdirectory(test)
endif(BUILD_TESTS)

###############################################################################
# Install
###############################################################################
install(TARGETS ${PROJECT_NAME}
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/softhsm
        )
if(ENABLE_STATIC)
        install(TARGETS ${PROJECT_NAME}-static
                DESTINATION ${CMAKE_INSTALL_LIBDIR}/softhsm
                )
endif()
