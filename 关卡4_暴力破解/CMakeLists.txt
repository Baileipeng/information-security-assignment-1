# 关卡 4：暴力破解 —— 多线程遍历 1024 个候选密钥并计时
add_executable(level4_bruteforce
    ${CMAKE_SOURCE_DIR}/src/sdes.cpp
    ${CMAKE_SOURCE_DIR}/src/bruteforce_mt.cpp
    main.cpp
)
target_include_directories(level4_bruteforce PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(level4_bruteforce PRIVATE Threads::Threads)
