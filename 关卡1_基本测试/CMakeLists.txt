# 关卡 1：基本测试 —— S-DES 8 bit 加解密
#
# 由根目录 CMakeLists.txt 通过
#   add_subdirectory("关卡1_基本测试" level1_basic_test)
# 引入：第二个参数是**二进制目录**，强制为 ASCII 名称，以规避
# MinGW 汇编器无法在非 ASCII 路径下写 .obj 的限制。
add_executable(level1_basic_test
    ${CMAKE_SOURCE_DIR}/src/sdes.cpp
    ${CMAKE_SOURCE_DIR}/src/bruteforce_mt.cpp
    main.cpp
)
target_include_directories(level1_basic_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(level1_basic_test PRIVATE Threads::Threads)
