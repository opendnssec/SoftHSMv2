project(softhsm2utiltest)

add_test(
	NAME ${PROJECT_NAME}-ml-dsa
	COMMAND ${CMAKE_COMMAND} -E env
			top_builddir=${CMAKE_BINARY_DIR}
			top_srcdir=${CMAKE_SOURCE_DIR}
			srcdir=${CMAKE_CURRENT_SOURCE_DIR}
			builddir=${CMAKE_CURRENT_BINARY_DIR}
			bash ${CMAKE_CURRENT_SOURCE_DIR}/mldsa44-import-key-test.sh
)

add_test(
		NAME ${PROJECT_NAME}-ml-kem
		COMMAND ${CMAKE_COMMAND} -E env
		top_builddir=${CMAKE_BINARY_DIR}
		top_srcdir=${CMAKE_SOURCE_DIR}
		srcdir=${CMAKE_CURRENT_SOURCE_DIR}
		builddir=${CMAKE_CURRENT_BINARY_DIR}
		bash ${CMAKE_CURRENT_SOURCE_DIR}/mlkem512-import-key-test.sh
)

# Make tests returning code 77 considered as skipped, to avoid marking the test suite as failed when running on an unsupported OpenSSL version or with a Botan-based SoftHSM2.
set_tests_properties(${PROJECT_NAME}-ml-dsa PROPERTIES SKIP_RETURN_CODE 77)
set_tests_properties(${PROJECT_NAME}-ml-kem PROPERTIES SKIP_RETURN_CODE 77)

if(WITH_FALCON)
    add_test(
        NAME ${PROJECT_NAME}-falcon512
        COMMAND ${CMAKE_COMMAND} -E env
            top_builddir=${CMAKE_BINARY_DIR}
            top_srcdir=${CMAKE_SOURCE_DIR}
            srcdir=${CMAKE_CURRENT_SOURCE_DIR}
            builddir=${CMAKE_CURRENT_BINARY_DIR}
            bash ${CMAKE_CURRENT_SOURCE_DIR}/falcon512-import-key-test.sh
    )
    set_tests_properties(${PROJECT_NAME}-falcon512 PROPERTIES SKIP_RETURN_CODE 77)
    add_test(
        NAME ${PROJECT_NAME}-falcon1024
        COMMAND ${CMAKE_COMMAND} -E env
            top_builddir=${CMAKE_BINARY_DIR}
            top_srcdir=${CMAKE_SOURCE_DIR}
            srcdir=${CMAKE_CURRENT_SOURCE_DIR}
            builddir=${CMAKE_CURRENT_BINARY_DIR}
            bash ${CMAKE_CURRENT_SOURCE_DIR}/falcon1024-import-key-test.sh
    )
    set_tests_properties(${PROJECT_NAME}-falcon1024 PROPERTIES SKIP_RETURN_CODE 77)
endif()
