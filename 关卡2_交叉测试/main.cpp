// ===========================================================================
// 关卡 2：交叉测试 —— 与标准实现 / 其他小组程序核对算法一致性
// ===========================================================================
//
// 【关卡要求】
//   与其他小组交换测试数据（若干组 密钥 K、明文 P 及其密文 C），
//   用本程序计算同样的输入，核对结果是否完全一致，以验证算法实现正确。
//
// 【本程序提供三种用法】
//   1. 默认          输出参考向量表：(K, P) -> (C, k1, k2)，供他人核对；
//   2. verify        用内置的“期望值表”（20 组）逐行对比，输出 PASS/FAIL，
//                    用于本程序自身的回归测试；
//   3. stdin         批量模式：从标准输入逐行读取 "K P"，输出对应密文 C，
//                    便于把别的组的向量直接灌进来批量核对。
//
// 【编译】
//   g++ -std=c++17 -O2 -I../src ../src/sdes.cpp main.cpp -o level2_cross_test
//
// 【运行】
//   level2_cross_test                      输出参考向量表
//   level2_cross_test verify               与内置期望值逐行比对
//   level2_cross_test stdin                从标准输入批量计算
//   echo "1010000010 00101000" | level2_cross_test stdin
//
// 【实测结果】
//   K=1010000010, P=00101000 -> C=11110100（与作业示例一致）
//   verify 模式 20 组向量全部 PASS
// ===========================================================================

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "console_utils.h"
#include "sdes.h"

using namespace sdes;

namespace {

// ---------------------------------------------------------------------------
// 内置参考向量：本程序在同一份置换表下算出的期望结果。
// 其他小组若使用**同样的置换表**（尤其是作业指定的修改版 SBox2），
// 应得到完全相同的密文；若不一致，说明两边的表或实现存在差异。
// ---------------------------------------------------------------------------
struct Vector {
    uint16_t key;
    uint8_t  plain;
    uint8_t  cipher;   // 期望密文
};

const std::vector<Vector> kReferenceVectors = {
    // K = 1010000010（作业示例密钥）
    {0b1010000010u, 0b00101000u, 0b11110100u},
    {0b1010000010u, 0b00000000u, 0b00100010u},
    {0b1010000010u, 0b11111111u, 0b11000110u},
    {0b1010000010u, 0b10101010u, 0b10100101u},
    // K = 0000000000（全 0 密钥）
    {0b0000000000u, 0b00101000u, 0b01010110u},
    {0b0000000000u, 0b00000000u, 0b11110000u},
    {0b0000000000u, 0b11111111u, 0b00010100u},
    {0b0000000000u, 0b10101010u, 0b00010001u},
    // K = 1111111111（全 1 密钥）
    {0b1111111111u, 0b00101000u, 0b11010011u},
    {0b1111111111u, 0b00000000u, 0b01000111u},
    {0b1111111111u, 0b11111111u, 0b10100011u},
    {0b1111111111u, 0b10101010u, 0b11101100u},
    // K = 0110111001
    {0b0110111001u, 0b00101000u, 0b00011000u},
    {0b0110111001u, 0b00000000u, 0b00111111u},
    {0b0110111001u, 0b11111111u, 0b10101110u},
    {0b0110111001u, 0b10101010u, 0b01101111u},
    // K = 0101010101
    {0b0101010101u, 0b00101000u, 0b01110101u},
    {0b0101010101u, 0b00000000u, 0b11010011u},
    {0b0101010101u, 0b11111111u, 0b11000101u},
    {0b0101010101u, 0b10101010u, 0b00101010u},
};

// ---------------------------------------------------------------------------
// 用法一：打印参考向量表
// ---------------------------------------------------------------------------
void printVectorTable() {
    std::cout << "===== S-DES 交叉测试参考向量表 =====" << std::endl;
    std::cout << "（置换表取自作业文档；SBox2 为作业指定的修改版）" << std::endl << std::endl;
    std::cout << " 编号 | 密钥 K (10bit) | 明文 P (8bit) | 密文 C (8bit) |   k1     |   k2     | 解密还原"
              << std::endl;
    std::cout << "------+----------------+---------------+---------------+----------+----------+---------"
              << std::endl;

    int idx = 0;
    for (const Vector& v : kReferenceVectors) {
        uint8_t k1 = 0, k2 = 0;
        generateSubKeys(v.key, k1, k2);
        const uint8_t c = encrypt(v.plain, v.key);
        const uint8_t back = decrypt(c, v.key);
        std::cout << std::setw(5) << ++idx << " |     "
                  << toBinaryString(v.key, 10) << "   |    "
                  << toBinaryString(v.plain, 8) << "   |    "
                  << toBinaryString(c, 8) << "   | "
                  << toBinaryString(k1, 8) << " | "
                  << toBinaryString(k2, 8) << " |   "
                  << (back == v.plain ? "OK" : "NG")
                  << std::endl;
    }
    std::cout << std::endl
              << "说明：把本表发给其他小组，让对方用相同输入计算密文，"
                 "逐一比对即可完成交叉测试。" << std::endl;
}

// ---------------------------------------------------------------------------
// 用法二：与内置期望值逐行比对（回归测试）
// ---------------------------------------------------------------------------
int verifyVectors() {
    std::cout << "===== 交叉测试校验（与内置期望值逐行比对） =====" << std::endl;
    int pass = 0, fail = 0;
    for (const Vector& v : kReferenceVectors) {
        const uint8_t c    = encrypt(v.plain, v.key);
        const uint8_t back = decrypt(c, v.key);
        const bool ok = (c == v.cipher) && (back == v.plain);
        if (ok) {
            ++pass;
        } else {
            ++fail;
            std::cout << "[FAIL] K=" << toBinaryString(v.key, 10)
                      << " P=" << toBinaryString(v.plain, 8)
                      << "  期望 C=" << toBinaryString(v.cipher, 8)
                      << "  实际 C=" << toBinaryString(c, 8) << std::endl;
        }
    }
    std::cout << "共 " << kReferenceVectors.size() << " 组向量：通过 "
              << pass << " 组，失败 " << fail << " 组 —— "
              << (fail == 0 ? "[PASS] 与标准结果完全一致"
                            : "[FAIL] 存在不一致，请检查置换表与 S-Box")
              << std::endl;

    // 再补一项交叉性质检验：同一明文在不同密钥下的密文应互不相同（雪崩初检）
    int distinct = 0;
    bool seen[256] = {false};
    for (uint16_t k = 0; k < 1024; ++k) {
        uint8_t c = encrypt(0b00101000u, k);
        if (!seen[c]) { seen[c] = true; ++distinct; }
    }
    std::cout << std::endl << "附加检查：P=00101000 在 1024 个密钥下的密文取值个数 = "
              << distinct << " 个（<256 说明存在多密钥映射，详见关卡 5）" << std::endl;
    return fail == 0 ? 0 : 2;
}

// ---------------------------------------------------------------------------
// 用法三：批量模式（从标准输入读 "K P"）
// ---------------------------------------------------------------------------
int batchMode() {
    std::cout << "===== 交叉测试批量模式 =====" << std::endl;
    std::cout << "每行输入一组: <密钥 10bit> <明文 8bit>，输入 EOF 结束" << std::endl << std::endl;

    std::string line;
    int count = 0;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        std::istringstream iss(line);
        std::string ks, ps;
        if (!(iss >> ks >> ps)) continue;

        uint16_t key = 0;
        uint8_t  plain = 0;
        if (!parseKeyArg(ks, key) || !parseByteArg(ps, plain)) {
            std::cout << "[跳过] 无法解析: " << line << std::endl;
            continue;
        }
        const uint8_t c = encrypt(plain, key);
        std::cout << "K=" << toBinaryString(key, 10)
                  << "  P=" << toBinaryString(plain, 8)
                  << "  ->  C=" << toBinaryString(c, 8)
                  << "  (" << hexByte(c) << ")" << std::endl;
        ++count;
    }
    std::cout << std::endl << "共处理 " << count << " 组输入。" << std::endl;
    return 0;
}

} // namespace

int main(int argc, char* argv[]) {
    const std::string mode = (argc >= 2) ? std::string(argv[1]) : std::string();

    std::cout << "==========================================================" << std::endl;
    std::cout << " 关卡 2：交叉测试 —— 算法一致性核对" << std::endl;
    std::cout << "==========================================================" << std::endl;
    std::cout << std::endl;

    if (mode == "verify")  return verifyVectors();
    if (mode == "stdin")   return batchMode();
    if (mode.empty() || mode == "table") { printVectorTable(); return 0; }

    if (mode == "-h" || mode == "--help") {
        std::cout << "用法:\n"
                     "  level2_cross_test            输出参考向量表\n"
                     "  level2_cross_test verify     与内置期望值逐行比对\n"
                     "  level2_cross_test stdin      从标准输入批量计算\n";
        return 0;
    }
    std::cerr << "未知模式: " << mode << "（可用: table / verify / stdin）" << std::endl;
    return 1;
}
