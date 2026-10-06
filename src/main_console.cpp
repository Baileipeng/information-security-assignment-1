// ---------------------------------------------------------------------------
// S-DES 控制台测试程序
//
// 用途：
//   1. 交叉测试（第 2 关）：以命令行方式对任意 (明文, 密钥) 计算密文，
//      便于与其他小组程序交换测试向量、验证算法一致性。
//   2. 暴力破解（第 4 关）：多线程遍历 1024 个候选密钥并计时。
//   3. 封闭测试（第 5 关）：对给定明文枚举全部匹配密钥，分析密钥多重性。
//   4. 自检 selftest：加解密往返一致性校验，输出标准测试向量。
//
// 用法示例：
//   sdes_console encrypt 1010000010 00101000
//   sdes_console decrypt 1010000010 <cipher8bits>
//   sdes_console textenc 1010000010 "This is a test"
//   sdes_console textdec 1010000010 <hex 或 二进制分组>
//   sdes_console bruteforce 00101000 10010010 [P2 C2 ...]   （支持多对）
//   sdes_console closure 00101000 10010010
//   sdes_console analysis          （第 5 关全文分析）
//   sdes_console selftest
// ---------------------------------------------------------------------------

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

#include "sdes.h"

using namespace sdes;

// 打印二进制字符串形式，同时给出十六进制，方便交叉测试时对照
static void printBits(const std::string& label, const std::string& bits) {
    std::cout << label << ": " << bits
              << "  (0x" << std::hex << std::stoul(bits, nullptr, 2) << std::dec << ")"
              << std::endl;
}

// 解析 8 bit 输入：支持二进制字符串或 0x 十六进制 / 十进制
static bool parseByteArg(const std::string& arg, uint8_t& out) {
    if (arg.find("0x") == 0 || arg.find("0X") == 0) {
        unsigned long v = std::stoul(arg, nullptr, 16);
        if (v > 0xFF) return false;
        out = static_cast<uint8_t>(v);
        return true;
    }
    if (arg.size() == 8 && (arg.find_first_not_of("01") == std::string::npos)) {
        uint16_t v = 0;
        return parseBinaryString(arg, 8, v) && (out = static_cast<uint8_t>(v), true);
    }
    try {
        unsigned long v = std::stoul(arg);
        if (v > 0xFF) return false;
        out = static_cast<uint8_t>(v);
        return true;
    } catch (...) {
        return false;
    }
}

static bool parseKeyArg(const std::string& arg, uint16_t& out) {
    if (arg.size() == 10 && (arg.find_first_not_of("01") == std::string::npos)) {
        return parseBinaryString(arg, 10, out);
    }
    try {
        unsigned long v = std::stoul(arg, nullptr, 0);
        if (v > 0x3FF) return false;
        out = static_cast<uint16_t>(v);
        return true;
    } catch (...) {
        return false;
    }
}

// --------------------------- 暴力破解（多线程） ------------------------------

struct BFChunk {
    uint16_t begin; // 本线程负责的密钥区间起点（含）
    uint16_t end;   // 终点（不含）
    std::vector<uint16_t> matched;
};

// 将 0..1023 均分给 nThreads 个线程，各自独立枚举，最后合并结果
static void bruteForceMT(const std::vector<std::pair<uint8_t, uint8_t>>& pairs,
                         std::vector<uint16_t>& result, double& elapsedMs,
                         int& threadCount) {
    unsigned hw = std::thread::hardware_concurrency();
    int nThreads = static_cast<int>(hw == 0 ? 1 : hw);
    if (nThreads > 16) nThreads = 16; // 密钥空间仅 1024，线程过多反而浪费
    if (nThreads < 1) nThreads = 1;

    std::vector<BFChunk> chunks(nThreads);
    for (int i = 0; i < nThreads; ++i) {
        chunks[i].begin = static_cast<uint16_t>(1024 * i / nThreads);
        chunks[i].end   = static_cast<uint16_t>(1024 * (i + 1) / nThreads);
    }

    auto t0 = std::chrono::high_resolution_clock::now();
    std::vector<std::thread> workers;
    for (int i = 0; i < nThreads; ++i) {
        workers.emplace_back([&chunks, &pairs, i]() {
            BFChunk& c = chunks[i];
            for (uint16_t key = c.begin; key < c.end; ++key) {
                bool ok = true;
                for (const auto& pc : pairs) {
                    if (encrypt(pc.first, key) != pc.second) {
                        ok = false;
                        break;
                    }
                }
                if (ok) c.matched.push_back(key);
            }
        });
    }
    for (auto& w : workers) w.join();
    auto t1 = std::chrono::high_resolution_clock::now();

    result.clear();
    for (const auto& c : chunks) {
        result.insert(result.end(), c.matched.begin(), c.matched.end());
    }
    std::sort(result.begin(), result.end());
    elapsedMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
    threadCount = nThreads;
}

// --------------------------- 第 5 关：封闭测试分析 ---------------------------

// 对每个明文统计“多个密钥加密到相同密文”的现象：
//   - collisionPlaintexts: 存在 K1 != K2 且 E(K1,P) == E(K2,P) 的明文个数
//   - maxKeysPerCipher:   单个 (P, C) 对最多被多少个密钥映射到
//   - sample:             若干典型案例，供报告引用
static void closureAnalysis() {
    int collisionPlaintexts = 0;
    int maxKeysPerCipher = 0;
    uint8_t maxCaseP = 0, maxCaseC = 0;

    for (int p = 0; p < 256; ++p) {
        // count[c] = 将明文 p 加密为密文 c 的密钥个数
        std::vector<int> count(256, 0);
        for (uint16_t k = 0; k < 1024; ++k) {
            ++count[encrypt(static_cast<uint8_t>(p), k)];
        }
        bool collide = false;
        for (int c = 0; c < 256; ++c) {
            if (count[c] > 1) {
                collide = true;
                if (count[c] > maxKeysPerCipher) {
                    maxKeysPerCipher = count[c];
                    maxCaseP = static_cast<uint8_t>(p);
                    maxCaseC = static_cast<uint8_t>(c);
                }
            }
        }
        if (collide) ++collisionPlaintexts;
    }

    std::cout << "==== S-DES 封闭测试分析（第 5 关） ====" << std::endl;
    std::cout << "明文空间 256 个取值逐一统计：" << std::endl;
    std::cout << "  存在多重密钥的明文个数 : " << collisionPlaintexts << " / 256" << std::endl;
    std::cout << "  单个 (P,C) 对的最大密钥数 : " << maxKeysPerCipher << std::endl;
    std::cout << "  典型案例 : P=" << toBinaryString(maxCaseP, 8)
              << ", C=" << toBinaryString(maxCaseC, 8) << std::endl;

    // 展示典型案例的全部匹配密钥
    std::vector<uint16_t> keys = findAllKeys(maxCaseP, maxCaseC);
    std::cout << "  该案例的全部匹配密钥 (" << keys.size() << " 个): ";
    for (size_t i = 0; i < keys.size(); ++i) {
        std::cout << toBinaryString(keys[i], 10);
        if (i + 1 < keys.size()) std::cout << ", ";
    }
    std::cout << std::endl;

    // 结论
    std::cout << std::endl;
    std::cout << "结论：";
    if (collisionPlaintexts > 0) {
        std::cout << "S-DES 不是双射密钥映射，存在不止一个密钥将同一明文"
                     "加密到相同密文（K1 != K2 但 C 相同）的情况。" << std::endl;
    } else {
        std::cout << "未观察到多重密钥现象。" << std::endl;
    }
}

// --------------------------- 自检 -------------------------------------------

static int selfTest() {
    int failures = 0;
    std::cout << "==== S-DES 自检 ====" << std::endl;

    // 1) 加解密往返一致性：遍历全部 256 明文 × 全部 1024 密钥
    for (uint16_t k = 0; k < 1024; ++k) {
        for (int p = 0; p < 256; ++p) {
            uint8_t c = encrypt(static_cast<uint8_t>(p), k);
            uint8_t d = decrypt(c, k);
            if (d != p) {
                if (failures < 5) {
                    std::cout << "[FAIL] K=" << toBinaryString(k, 10)
                              << " P=" << toBinaryString(static_cast<uint8_t>(p), 8)
                              << " 往返失败" << std::endl;
                }
                ++failures;
            }
        }
    }
    std::cout << (failures == 0 ? "[PASS]" : "[FAIL]")
              << " 加解密往返一致性: 256 x 1024 = 262144 组全部"
              << (failures == 0 ? "通过" : "存在失败") << std::endl;

    // 2) 输出几组标准测试向量，供交叉测试（第 2 关）使用
    std::cout << std::endl << "交叉测试参考向量：" << std::endl;
    const uint16_t demoKeys[] = {0b1010000010u, 0b0000000000u, 0b1111111111u,
                                 0b0110111001u};
    for (uint16_t k : demoKeys) {
        uint8_t p = 0b00101000;
        uint8_t c = encrypt(p, k);
        std::cout << "  K=" << toBinaryString(k, 10)
                  << "  P=" << toBinaryString(p, 8)
                  << "  -> C=" << toBinaryString(c, 8) << std::endl;
    }
    return failures;
}

// --------------------------- 主入口 -----------------------------------------

static void printUsage() {
    std::cout <<
        "用法:\n"
        "  sdes_console encrypt <key10> <plain8>\n"
        "  sdes_console decrypt <key10> <cipher8>\n"
        "  sdes_console textenc <key10> \"文本\"\n"
        "  sdes_console textdec <key10> <hex分组,如 1A2B3C>\n"
        "  sdes_console bruteforce <plain8> <cipher8> [P2 C2 ...]\n"
        "  sdes_console closure <plain8> <cipher8>\n"
        "  sdes_console analysis\n"
        "  sdes_console selftest\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage();
        return 1;
    }
    std::string cmd = argv[1];

    if (cmd == "encrypt" && argc >= 4) {
        uint16_t key; uint8_t p;
        if (!parseKeyArg(argv[2], key) || !parseByteArg(argv[3], p)) {
            std::cerr << "参数格式错误" << std::endl; return 1;
        }
        uint8_t c = encrypt(p, key);
        printBits("明文 P", toBinaryString(p, 8));
        printBits("密文 C", toBinaryString(c, 8));
        return 0;
    }

    if (cmd == "decrypt" && argc >= 4) {
        uint16_t key; uint8_t c;
        if (!parseKeyArg(argv[2], key) || !parseByteArg(argv[3], c)) {
            std::cerr << "参数格式错误" << std::endl; return 1;
        }
        uint8_t p = decrypt(c, key);
        printBits("密文 C", toBinaryString(c, 8));
        printBits("明文 P", toBinaryString(p, 8));
        return 0;
    }

    if (cmd == "textenc" && argc >= 4) {
        uint16_t key;
        if (!parseKeyArg(argv[2], key)) { std::cerr << "密钥格式错误" << std::endl; return 1; }
        std::string text = argv[3];
        std::ostringstream bin, hexs;
        for (unsigned char ch : text) {
            uint8_t c = encrypt(ch, key);
            bin << toBinaryString(c, 8) << ' ';
            hexs << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
        std::cout << "文本 : " << text << std::endl;
        std::cout << "ASCII密文(二进制): " << bin.str() << std::endl;
        std::cout << "ASCII密文(HEX)   : " << hexs.str() << std::endl;
        return 0;
    }

    if (cmd == "textdec" && argc >= 4) {
        uint16_t key;
        if (!parseKeyArg(argv[2], key)) { std::cerr << "密钥格式错误" << std::endl; return 1; }
        std::string hexs = argv[3];
        if (hexs.size() % 2 != 0) { std::cerr << "HEX 长度须为偶数" << std::endl; return 1; }
        std::string out;
        for (size_t i = 0; i < hexs.size(); i += 2) {
            unsigned long v = std::stoul(hexs.substr(i, 2), nullptr, 16);
            out.push_back(static_cast<char>(decrypt(static_cast<uint8_t>(v), key)));
        }
        std::cout << "解密文本: " << out << std::endl;
        return 0;
    }

    if (cmd == "bruteforce" && argc >= 4) {
        std::vector<std::pair<uint8_t, uint8_t>> pairs;
        for (int i = 2; i + 1 < argc; i += 2) {
            uint8_t p, c;
            if (!parseByteArg(argv[i], p) || !parseByteArg(argv[i + 1], c)) {
                std::cerr << "明文/密文参数格式错误" << std::endl; return 1;
            }
            pairs.emplace_back(p, c);
        }
        std::vector<uint16_t> keys; double ms; int threads;
        bruteForceMT(pairs, keys, ms, threads);

        std::cout << "==== 暴力破解（第 4 关） ====" << std::endl;
        std::cout << "已知明密文对 " << pairs.size() << " 组:" << std::endl;
        for (const auto& pc : pairs) {
            std::cout << "  P=" << toBinaryString(pc.first, 8)
                      << "  C=" << toBinaryString(pc.second, 8) << std::endl;
        }
        std::cout << "使用线程数 : " << threads << std::endl;
        std::cout << "耗时       : " << std::fixed << std::setprecision(3) << ms << " ms" << std::endl;
        std::cout << "匹配密钥数 : " << keys.size() << std::endl;
        for (uint16_t k : keys) {
            std::cout << "  Key = " << toBinaryString(k, 10)
                      << "  (0x" << std::hex << std::setw(3) << std::setfill('0')
                      << k << std::dec << ")" << std::endl;
        }
        return 0;
    }

    if (cmd == "closure" && argc >= 4) {
        uint8_t p, c;
        if (!parseByteArg(argv[2], p) || !parseByteArg(argv[3], c)) {
            std::cerr << "参数格式错误" << std::endl; return 1;
        }
        std::vector<uint16_t> keys = findAllKeys(p, c);
        std::cout << "==== 封闭测试（第 5 关） ====" << std::endl;
        printBits("明文 P", toBinaryString(p, 8));
        printBits("密文 C", toBinaryString(c, 8));
        std::cout << "匹配密钥 " << keys.size() << " 个:" << std::endl;
        for (uint16_t k : keys) std::cout << "  Key = " << toBinaryString(k, 10) << std::endl;
        return 0;
    }

    if (cmd == "analysis") { closureAnalysis(); return 0; }

    if (cmd == "selftest") { return selfTest() == 0 ? 0 : 2; }

    printUsage();
    return 1;
}
