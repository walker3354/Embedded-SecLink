add_executable(test_HashTree test_HashTree.cpp)
target_link_libraries(test_HashTree PRIVATE esl GTest::gtest_main)

add_executable(test_EccCore test_EccCore.cpp)
target_link_libraries(test_EccCore PRIVATE esl GTest::gtest_main)

add_executable(test_BlsCore test_BlsCore.cpp)
target_link_libraries(test_BlsCore PRIVATE esl GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(test_HashTree)
gtest_discover_tests(test_EccCore)
gtest_discover_tests(test_BlsCore)
