cmake_minimum_required(VERSION 3.16)
project(SDES_Assignment1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

# ---------------- 目标 1：核心算法 + 控制台程序（无 Qt 依赖） ----------------
add_executable(sdes_console
    src/sdes.cpp
    src/sdes_analysis.cpp
    src/main_console.cpp
)
# 控制台程序只依赖标准库，任何平台可直接编译

# ---------------- 目标 2：Qt GUI 程序 ---------------------------------------
# 依次尝试 Qt6 / Qt5；构建 GUI 需要 Widgets 与 Concurrent 模块。
# 若本机未安装 Qt，则跳过 GUI，仅构建控制台程序。
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
        message(WARNING "未找到 Qt，仅构建控制台程序 sdes_console")
    endif()
endif()

if(Qt6_FOUND OR Qt5_FOUND)
    find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Concurrent)

    add_executable(sdes_gui
        src/sdes.cpp
        src/sdes_analysis.cpp
        src/main_gui.cpp
        src/mainwindow.cpp
        src/mainwindow.h
    )
    target_link_libraries(sdes_gui PRIVATE
        Qt${QT_VERSION_MAJOR}::Widgets
        Qt${QT_VERSION_MAJOR}::Concurrent
    )
    set_target_properties(sdes_gui PROPERTIES
        WIN32_EXECUTABLE ON   # Windows 下隐藏控制台黑窗
    )
endif()
