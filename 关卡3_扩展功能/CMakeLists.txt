# 关卡 3：扩展功能 —— ASCII 字符串分组加解密（ECB）
add_executable(level3_ascii_text
    ${CMAKE_SOURCE_DIR}/src/sdes.cpp
    ${CMAKE_SOURCE_DIR}/src/bruteforce_mt.cpp
    main.cpp
)
target_include_directories(level3_ascii_text PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(level3_ascii_text PRIVATE Threads::Threads)
