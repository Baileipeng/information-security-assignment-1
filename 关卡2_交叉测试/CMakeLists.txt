# 关卡 2：交叉测试 —— 算法一致性核对
add_executable(level2_cross_test
    ${CMAKE_SOURCE_DIR}/src/sdes.cpp
    ${CMAKE_SOURCE_DIR}/src/bruteforce_mt.cpp
    main.cpp
)
target_include_directories(level2_cross_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(level2_cross_test PRIVATE Threads::Threads)
