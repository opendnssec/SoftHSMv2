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

set(DEPENDENCIES softhsm_common-obj
                 softhsm_crypto-obj
                 softhsm_datamgr-obj
                 softhsm_handlemgr-obj
                 softhsm_objectstore-obj
                 softhsm_sessionmgr-obj
                 softhsm_slotmgr-obj
                 )

set(OBJECT_FILES $<TARGET_OBJECTS:softhsm_common-obj>
                 $<TARGET_OBJECTS:softhsm_crypto-obj>
                 $<TARGET_OBJECTS:softhsm_datamgr-obj>
                 $<TARGET_OBJECTS:softhsm_handlemgr-obj>
                 $<TARGET_OBJECTS:softhsm_objectstore-obj>
                 $<TARGET_OBJECTS:softhsm_sessionmgr-obj>
                 $<TARGET_OBJECTS:softhsm_slotmgr-obj>
                 )


###############################################################################
# Static Library Config
###############################################################################
add_library(${PROJECT_NAME}-static STATIC ${SOURCES} ${OBJECT_FILES})
add_dependencies(${PROJECT_NAME}-static ${DEPENDENCIES})
set_target_properties(${PROJECT_NAME}-static
                      PROPERTIES OUTPUT_NAME ${PROJECT_NAME}
                      )
generate_export_header(${PROJECT_NAME}-static)

###############################################################################
# Shared Library Config
###############################################################################
add_library(${PROJECT_NAME} SHARED ${SOURCES} ${OBJECT_FILES})
add_dependencies(${PROJECT_NAME} ${DEPENDENCIES})
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
install(TARGETS ${PROJECT_NAME} ${PROJECT_NAME}-static
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/softhsm
        )
