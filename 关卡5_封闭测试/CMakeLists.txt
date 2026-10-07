# 关卡 5：封闭测试 —— 密钥多重性分析（需要 sdes_analysis 模块）
add_executable(level5_closure
    ${CMAKE_SOURCE_DIR}/src/sdes.cpp
    ${CMAKE_SOURCE_DIR}/src/bruteforce_mt.cpp
    ${CMAKE_SOURCE_DIR}/src/sdes_analysis.cpp
    main.cpp
)
target_include_directories(level5_closure PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(level5_closure PRIVATE Threads::Threads)
