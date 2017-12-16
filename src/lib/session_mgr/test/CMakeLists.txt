project(sessionmgrtest)

set(SOURCES sessionmgrtest.cpp
            SessionManagerTests.cpp
            )

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} softhsm2-static ${CRYPTO_LIBS} ${CPPUNIT_LIBS})

add_test(${PROJECT_NAME} ${PROJECT_NAME})
