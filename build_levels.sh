#!/usr/bin/env bash
# ===========================================================================
# 一键编译（并可选运行）各关卡程序
#
#   ./build_levels.sh            只编译，产物输出到 bin/
#   ./build_levels.sh run        编译后依次运行 5 个关卡程序
#   ./build_levels.sh run save   编译、运行，并把输出保存到 关卡测试输出/
#
# 环境变量 CXX 可指定编译器（默认 g++）。
# 需要 C++17 与 pthread（Windows 下的 MinGW 自带 winpthread）。
# ===========================================================================
set -e
cd "$(dirname "$0")"

CXX="${CXX:-g++}"
FLAGS=(-std=c++17 -O2 -Wall -I src)
CORE=(src/sdes.cpp src/bruteforce_mt.cpp)
ANALYSIS=(src/sdes_analysis.cpp)
OUTDIR=bin
mkdir -p "$OUTDIR"

echo "编译器: $($CXX --version | head -1)"

compile() {           # compile <输出名> <源文件...>
    local name="$1"; shift
    echo "  -> $name"
    "$CXX" "${FLAGS[@]}" "$@" -o "$OUTDIR/$name" -pthread
}

echo "== 编译公共控制台程序 =="
compile sdes_console "${CORE[@]}" "${ANALYSIS[@]}" src/main_console.cpp

echo "== 关卡 1：基本测试 =="
compile level1_basic_test "${CORE[@]}" "关卡1_基本测试/main.cpp"

echo "== 关卡 2：交叉测试 =="
compile level2_cross_test "${CORE[@]}" "关卡2_交叉测试/main.cpp"

echo "== 关卡 3：扩展功能 =="
compile level3_ascii_text "${CORE[@]}" "关卡3_扩展功能/main.cpp"

echo "== 关卡 4：暴力破解 =="
compile level4_bruteforce "${CORE[@]}" "关卡4_暴力破解/main.cpp"

echo "== 关卡 5：封闭测试 =="
compile level5_closure "${CORE[@]}" "${ANALYSIS[@]}" "关卡5_封闭测试/main.cpp"

echo
echo "编译完成，产物位于 $OUTDIR/"

# --------------------------- 可选：运行各关卡 -------------------------------
if [ "$1" = "run" ]; then
    SAVE=""
    if [ "$2" = "save" ]; then
        SAVE=1
        mkdir -p "关卡测试输出"
        echo "运行输出将保存到 关卡测试输出/"
    fi

    run() {           # run <输出文件名> <命令...>
        local tag="$1"; shift
        echo
        echo "################ $tag ################"
        if [ -n "$SAVE" ]; then
            "$@" 2>&1 | tee "关卡测试输出/$tag.txt"
        else
            "$@"
        fi
    }

    WIN=""
    case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) WIN=1;; esac
    EXE=""; [ -n "$WIN" ] && EXE=".exe"

    run "关卡1_基本测试"   "$OUTDIR/level1_basic_test$EXE"
    run "关卡2_交叉测试"   "$OUTDIR/level2_cross_test$EXE" verify
    run "关卡3_扩展功能"   "$OUTDIR/level3_ascii_text$EXE"
    run "关卡4_暴力破解"   "$OUTDIR/level4_bruteforce$EXE" --stress 100000
    run "关卡5_封闭测试"   "$OUTDIR/level5_closure$EXE"
fi
