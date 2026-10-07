cmake_minimum_required(VERSION 3.16)
project(SDES_Assignment1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# 目录结构说明
#
#   src/                     公共源码（所有目标共用）
#     sdes.*                 核心算法：置换表、Keygen、加解密、暴力破解
#     bruteforce_mt.*        第 4 关：多线程暴力破解模块
#     sdes_analysis.*        第 5 关：密钥多重性（封闭测试）分析模块
#     console_utils.h        命令行参数解析 / 位串打印（纯头文件）
#     main_console.cpp       一体化命令行工具（所有关卡功能的总入口）
#     main_gui.cpp            Qt GUI 入口（5 个页签对应 5 个关卡）
#     关卡1_基本测试/ ~ 关卡5_封闭测试/   各关卡的独立示例程序 + 说明
#
# 生成器建议使用 Ninja：
#   cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
#   cmake --build build
#
# ⚠ Windows + MinGW 的已知限制：汇编器无法在**非 ASCII 路径**下创建 .obj，
#   而本仓库的关卡目录名是中文。因此下面用 add_subdirectory(<中文源目录>
#   <ASCII 二进制目录>) 的形式，把所有目标文件都放到 ASCII 路径下，
#   既保留中文目录命名，又能正常编译。
#   （MinGW Makefiles 生成器还会把中文源路径传给编译器时乱码，请用 Ninja，
#     或直接使用仓库根的一键脚本 ./build_levels.sh）
# ---------------------------------------------------------------------------

find_package(Threads REQUIRED)

# --------------------------- 目标 0：一体化命令行工具 ------------------------
add_executable(sdes_console
    src/sdes.cpp
    src/bruteforce_mt.cpp
    src/sdes_analysis.cpp
    src/main_console.cpp
)
target_include_directories(sdes_console PRIVATE src)
target_link_libraries(sdes_console PRIVATE Threads::Threads)

# --------------------------- 目标 1~5：各关卡独立程序 ------------------------
# 每个关卡目录下都有各自的 CMakeLists.txt，便于单独构建与阅读
add_subdirectory("关卡1_基本测试" level1_basic_test)
add_subdirectory("关卡2_交叉测试" level2_cross_test)
add_subdirectory("关卡3_扩展功能" level3_ascii_text)
add_subdirectory("关卡4_暴力破解" level4_bruteforce)
add_subdirectory("关卡5_封闭测试" level5_closure)

# --------------------------- 目标 6：Qt GUI 程序 -----------------------------
# 依次尝试 Qt6 / Qt5；需要 Widgets 与 Concurrent 模块。
# 若本机未安装 Qt，则跳过 GUI，仅构建命令行工具与各关卡程序。
find_package(Qt6 QUIET COMPONENTS Widgets Concurrent)
if(Qt6_FOUND)
    message(STATUS "使用 Qt6 构建 GUI")
    set(QT_VERSION_MAJOR 6)
else()
    find_package(Qt5 QUIET COMPONENTS Widgets Concurrent)
    if(Qt5_FOUND)
        message(STATUS "使用 Qt5 构建 GUI")
        set(QT_VERSION_MAJOR 5)
    else()
        message(WARNING "未找到 Qt，跳过 GUI 目标 sdes_gui")
    endif()
endif()

if(Qt6_FOUND OR Qt5_FOUND)
    find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Concurrent)

    add_executable(sdes_gui
        src/sdes.cpp
        src/bruteforce_mt.cpp
        src/sdes_analysis.cpp
        src/main_gui.cpp
        src/mainwindow.cpp
        src/mainwindow.h
    )
    target_include_directories(sdes_gui PRIVATE src)
    target_link_libraries(sdes_gui PRIVATE
        Threads::Threads
        Qt${QT_VERSION_MAJOR}::Widgets
        Qt${QT_VERSION_MAJOR}::Concurrent
    )
    # 只有 GUI 需要 moc，其余目标关闭 AUTOMOC 以加快构建
    set_target_properties(sdes_gui PROPERTIES
        AUTOMOC ON
        WIN32_EXECUTABLE ON   # Windows 下隐藏控制台黑窗
    )
endif()
