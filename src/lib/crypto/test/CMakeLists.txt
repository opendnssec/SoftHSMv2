project(cryptotest)

set(SOURCES cryptotest.cpp
            AESTests.cpp
            DESTests.cpp
            DHTests.cpp
            DSATests.cpp
            ECDHTests.cpp
            ECDSATests.cpp
            GOSTTests.cpp
            HashTests.cpp
            MacTests.cpp
            RNGTests.cpp
            RSATests.cpp
            chisq.c
            ent.c
            iso8859.c
            randtest.c
            )

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} softhsm2-static ${CRYPTO_LIBS} ${CPPUNIT_LIBS})

add_test(${PROJECT_NAME} ${PROJECT_NAME})
