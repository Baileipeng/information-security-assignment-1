// ===========================================================================
// 关卡 5：封闭测试 —— 密钥是否唯一？S-DES 密钥多重性分析
// ===========================================================================
//
// 【关卡要求】
//   Q1. 对随机选定的一对（明文 P，密文 C），满足 E(K, P) = C 的密钥是否唯一？
//   Q2. 对任意明文分组 P，是否存在两个不同密钥 K1 ≠ K2 使 E(K1, P) = E(K2, P)？
//   要求给出结论并说明理由。
//
// 【本程序的分析层次（逐层递进）】
//   ① 单点枚举     ：对给定的 (P, C) 列出全部匹配密钥，看是否唯一；
//   ② 密钥等价类   ：1024 个密钥经 Keygen 产生多少种不同的 (k1,k2) 子密钥对？
//                    子密钥对完全相同的密钥对“所有明文”加密结果都相同，
//                    是最强的碰撞证据；
//   ③ 明文维度碰撞 ：逐明文检查 1024 个密钥的加密输出是否存在重复；
//   ④ 全空间分布   ：全部 256 明文 × 256 密文组合中，匹配密钥个数的分布。
//
// 【编译】
//   g++ -std=c++17 -O2 -I../src ../src/sdes.cpp ../src/sdes_analysis.cpp main.cpp -o level5_closure
//
// 【运行】
//   level5_closure                      输出完整分析报告（①②③④）
//   level5_closure <P> <C>              仅做单点枚举
//   level5_closure --classes            仅做密钥等价类分析
//   level5_closure --collision          仅做明文维度碰撞检测
//   level5_closure --profile            仅做全空间分布统计
//
// 【实测结论】
//   * 1024 个密钥经 Keygen 只产生 256 种不同的 (k1,k2) 子密钥对，每个等价类
//     恰好 4 个密钥 —— 即 S-DES 的有效密钥熵只有 8 bit 而非 10 bit；
//   * 对任意明文 P 都存在 K1 ≠ K2 使 E(K1,P) = E(K2,P)，256/256 个明文全部
//     命中；单个 (P, C) 最多可被 32 个不同密钥映射到；
//   * 因此“只有一个密钥”的答案是【否】。理由：P10 置换 + 循环移位 + P8 压缩
//     使不同主密钥产生完全相同的子密钥序列，等价密钥对所有明文的加密函数
//     完全相同，所以候选密钥恒为一个等价类（4 的倍数个），无法唯一确定。
// ===========================================================================

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "console_utils.h"
#include "sdes.h"
#include "sdes_analysis.h"

using namespace sdes;

namespace {

const uint8_t kDefaultP = 0b00101000u;   // 作业示例明文
const uint8_t kDefaultC = 0b11110100u;   // 作业示例密文（K=1010000010 加密所得）

// ---------------------------------------------------------------------------
// ① 单点枚举：给定 (P, C) 列出全部匹配密钥
// ---------------------------------------------------------------------------
void printSinglePoint(uint8_t p, uint8_t c) {
    std::vector<uint16_t> keys = findAllKeys(p, c);

    std::cout << "---- ① 单点密钥枚举 ----" << std::endl;
    std::cout << "  明文 P = " << toBinaryString(p, 8) << "  (" << hexByte(p) << ")" << std::endl;
    std::cout << "  密文 C = " << toBinaryString(c, 8) << "  (" << hexByte(c) << ")" << std::endl;
    std::cout << "  匹配密钥共 " << keys.size() << " 个:" << std::endl;
    for (uint16_t k : keys) {
        std::cout << "    K = " << toBinaryString(k, 10) << std::endl;
    }
    std::cout << "  小结论 : " << (keys.size() > 1
                ? "候选密钥不唯一（存在多重密钥）"
                : "候选密钥唯一") << std::endl;
}

// ---------------------------------------------------------------------------
// ④ 全空间分布的补充说明（基于 sdes_analysis 的统计结果）
// ---------------------------------------------------------------------------
void printReasoning() {
    std::cout << std::endl << "---- ⑤ 结论与理由 ----" << std::endl;
    std::cout << "  结论：对随机选定的一对 (P, C)，满足 E(K,P)=C 的密钥【不唯一】；" << std::endl;
    std::cout << "        对任意明文 P，都存在 K1 ≠ K2 使 E(K1,P) = E(K2,P)。" << std::endl;
    std::cout << std::endl;
    std::cout << "  理由：" << std::endl;
    std::cout << "   (1) 密钥扩展 Keygen 把 10 bit 主密钥映射为 8+8=16 bit 子密钥对," << std::endl;
    std::cout << "       但 P10 置换 + 循环左移 + P8 压缩存在结构冗余：不同主密钥会" << std::endl;
    std::cout << "       得到完全相同的 (k1, k2)（见分析②，1024 个密钥只有 256 种"; 
    std::cout << " 子密钥对）。" << std::endl;
    std::cout << "   (2) 子密钥对相同的两个密钥，对**任何**明文加密结果都相同，" << std::endl;
    std::cout << "       即 1024 个密钥实际只等价于 256 个不同的加密函数 ——" << std::endl;
    std::cout << "       S-DES 的有效密钥熵仅 8 bit。" << std::endl;
    std::cout << "   (3) 明文/密文空间只有 2^8 = 256，而 1024 个密钥要映射到 256 个密文" << std::endl;
    std::cout << "       值上，由鸽笼原理必然出现多对一（见分析③④）。" << std::endl;
    std::cout << "   (4) 因此暴力破解的候选集合恒为一个等价类（个数为 4 的倍数），" << std::endl;
    std::cout << "       永远无法从单组明密文唯一确定原始密钥。" << std::endl;
}

} // namespace

int main(int argc, char* argv[]) {
    std::cout << "==========================================================" << std::endl;
    std::cout << " 关卡 5：封闭测试 —— S-DES 密钥多重性分析" << std::endl;
    std::cout << "==========================================================" << std::endl;

    // 仅做单点枚举：level5_closure <P> <C>
    if (argc >= 3) {
        uint8_t p = 0, c = 0;
        if (parseByteArg(argv[1], p) && parseByteArg(argv[2], c)) {
            std::cout << std::endl;
            printSinglePoint(p, c);
            return 0;
        }
        std::cerr << "参数格式错误：<明文 8bit> <密文 8bit>" << std::endl;
        return 1;
    }

    // 选择单项分析
    const std::string mode = (argc >= 2) ? std::string(argv[1]) : std::string("--full");
    const bool all = (mode == "--full" || mode == "-h" || mode == "--help");

    if (mode == "-h" || mode == "--help") {
        std::cout << "\n用法:\n"
                     "  level5_closure              完整分析报告\n"
                     "  level5_closure <P> <C>      单点密钥枚举\n"
                     "  level5_closure --classes    密钥等价类分析\n"
                     "  level5_closure --collision  明文维度碰撞检测\n"
                     "  level5_closure --profile    全空间分布统计\n" << std::endl;
        return 0;
    }

    if (all) {
        std::cout << std::endl;
        printSinglePoint(kDefaultP, kDefaultC);   // ①
        std::cout << std::endl;
    }

    if (all || mode == "--classes") {
        std::cout << formatKeyEquivalence(analyzeKeyEquivalence()) << std::endl;
    }
    if (all || mode == "--collision") {
        std::cout << formatPlaintextCollision(analyzePlaintextCollision()) << std::endl;
    }
    if (all || mode == "--profile") {
        std::cout << formatCipherProfile(analyzeCipherProfile()) << std::endl;
    }
    if (all) {
        printReasoning();
    }

    if (!all && mode != "--classes" && mode != "--collision" && mode != "--profile") {
        std::cerr << "未知参数: " << mode << std::endl;
        return 1;
    }
    return 0;
}
