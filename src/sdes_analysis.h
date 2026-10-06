#ifndef SDES_ANALYSIS_H
#define SDES_ANALYSIS_H

#include <cstdint>
#include <utility>
#include <vector>

#include "sdes.h"

// ---------------------------------------------------------------------------
// S-DES 密钥多重性（封闭测试 / 第 5 关）分析模块
//
// 回答两个问题：
//   Q1. 对给定的一对（明文 P，密文 C），满足 E(K,P)=C 的密钥是否唯一？
//   Q2. 对任意明文分组 P，是否存在两个不同密钥 K1 ≠ K2 使 E(K1,P)=E(K2,P)？
//
// 分析分三个层次递进：
//   ① 密钥等价类：1024 个密钥经过 Keygen 得到多少种不同的 (k1,k2) 子密钥对；
//      子密钥对相同的密钥，对**所有**明文加密结果都相同，是最强的碰撞证据。
//   ② 明文维度碰撞：逐明文检查 1024 个密钥的加密输出是否存在重复值。
//   ③ 全空间分布：对全部 256 明文 × 256 密文组合，统计"匹配密钥个数"的分布。
// ---------------------------------------------------------------------------
namespace sdes {

// ① 密钥等价类分析
struct KeyEquivalenceReport {
    int distinctSubKeyPairs = 0;   // 不同 (k1,k2) 子密钥对的数量
    int maxClassSize = 0;          // 最大等价类规模（密钥个数）
    int minClassSize = 0;          // 最小等价类规模
    // 等价类：每个元素是"子密钥对 + 全部等价密钥"的列表
    struct KeyClass {
        uint8_t k1 = 0;
        uint8_t k2 = 0;
        std::vector<uint16_t> keys;  // 该等价类下的全部 10 bit 密钥
    };
    std::vector<KeyClass> classes;
};

// ② 明文维度碰撞分析
struct PlaintextCollisionReport {
    int plaintextsWithCollision = 0;      // 存在碰撞的明文个数（最多 256）
    long long totalCollisionPairs = 0;    // Σ C(count,2)：同一明文下"密钥对"碰撞总数
    int maxMultiplicity = 0;              // 单个 (P,C) 的最大匹配密钥数
    uint8_t exampleP = 0;                 // 最大多重性案例
    uint8_t exampleC = 0;
    std::vector<uint16_t> exampleKeys;    // 该案例的全部匹配密钥
    long long totalKeysAllPlaintexts = 0; // 参与统计的密钥总数 = 256 × 1024
};

// ③ 全空间 (P,C) 匹配密钥数分布
struct CipherProfileReport {
    std::vector<int> pairCountNthKey;  // pairCountNthKey[n] = 恰好有 n 个匹配密钥的 (P,C) 对数
    int nonEmptyPairs = 0;             // 至少有一个密钥的 (P,C) 对数
    int multiKeyPairs = 0;             // 匹配密钥数 ≥ 2 的 (P,C) 对数
    int maxKeys = 0;                   // 最大匹配密钥数
    uint8_t maxP = 0, maxC = 0;        // 最大案例
};

// 执行三项分析
KeyEquivalenceReport     analyzeKeyEquivalence();
PlaintextCollisionReport analyzePlaintextCollision();
CipherProfileReport      analyzeCipherProfile();

// 把分析结果格式化为可读报告文本（控制台 / GUI 共用）
std::string formatKeyEquivalence(const KeyEquivalenceReport& r);
std::string formatPlaintextCollision(const PlaintextCollisionReport& r);
std::string formatCipherProfile(const CipherProfileReport& r);

} // namespace sdes

#endif // SDES_ANALYSIS_H
