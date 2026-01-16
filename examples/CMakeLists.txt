add_executable(BlsCore_example BlsCore_example.cpp)
target_link_libraries(BlsCore_example PRIVATE esl)

add_executable(EccCore_example EccCore_example.cpp)
target_link_libraries(EccCore_example PRIVATE esl)

add_executable(Time_example Time_example.cpp)
target_link_libraries(Time_example PRIVATE esl)