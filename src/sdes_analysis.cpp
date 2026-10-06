#include "sdes_analysis.h"

#include <algorithm>
#include <map>
#include <sstream>

namespace sdes {

// ---------------------------------------------------------------------------
// ① 密钥等价类分析
//    若两个密钥经 Keygen 得到相同的 (k1, k2)，则它们的加密函数完全相同，
//    对任意明文 P 都有 E(K1,P) = E(K2,P) —— 这是最直接的碰撞证据。
// ---------------------------------------------------------------------------
KeyEquivalenceReport analyzeKeyEquivalence() {
    KeyEquivalenceReport report;

    // key -> 子密钥对；按 (k1,k2) 归并密钥
    std::map<std::pair<uint8_t, uint8_t>, std::vector<uint16_t>> grouped;
    for (uint16_t key = 0; key < 1024; ++key) {
        uint8_t k1, k2;
        generateSubKeys(key, k1, k2);
        grouped[{k1, k2}].push_back(key);
    }

    report.distinctSubKeyPairs = static_cast<int>(grouped.size());
    report.maxClassSize = 0;
    report.minClassSize = 0x7FFFFFFF;

    for (auto& entry : grouped) {
        KeyEquivalenceReport::KeyClass cls;
        cls.k1 = entry.first.first;
        cls.k2 = entry.first.second;
        cls.keys = entry.second;
        report.classes.push_back(cls);

        int size = static_cast<int>(cls.keys.size());
        report.maxClassSize = std::max(report.maxClassSize, size);
        report.minClassSize = std::min(report.minClassSize, size);
    }
    if (report.classes.empty()) report.minClassSize = 0;
    return report;
}

// ---------------------------------------------------------------------------
// ② 明文维度碰撞分析
//    对每个明文 P，遍历 1024 个密钥得到 1024 个密文值，统计是否有重复。
// ---------------------------------------------------------------------------
PlaintextCollisionReport analyzePlaintextCollision() {
    PlaintextCollisionReport report;
    report.totalKeysAllPlaintexts = 256LL * 1024LL;

    for (int p = 0; p < 256; ++p) {
        int count[256] = {0};
        for (uint16_t key = 0; key < 1024; ++key) {
            ++count[encrypt(static_cast<uint8_t>(p), key)];
        }

        bool collide = false;
        for (int c = 0; c < 256; ++c) {
            if (count[c] >= 2) {
                collide = true;
                // 同一明文下有 count[c] 个密钥给出同一密文，可组成 C(n,2) 个碰撞密钥对
                report.totalCollisionPairs +=
                    1LL * count[c] * (count[c] - 1) / 2;
                if (count[c] > report.maxMultiplicity) {
                    report.maxMultiplicity = count[c];
                    report.exampleP = static_cast<uint8_t>(p);
                    report.exampleC = static_cast<uint8_t>(c);
                }
            }
        }
        if (collide) ++report.plaintextsWithCollision;
    }

    report.exampleKeys = findAllKeys(report.exampleP, report.exampleC);
    return report;
}

// ---------------------------------------------------------------------------
// ③ 全空间 (P,C) 匹配密钥数分布
//    枚举 256 × 256 个 (P,C) 组合，统计每个组合对应的密钥个数分布。
// ---------------------------------------------------------------------------
CipherProfileReport analyzeCipherProfile() {
    CipherProfileReport report;
    report.pairCountNthKey.assign(1025, 0); // 下标 n = 匹配密钥个数

    for (int p = 0; p < 256; ++p) {
        int count[256] = {0};
        for (uint16_t key = 0; key < 1024; ++key) {
            ++count[encrypt(static_cast<uint8_t>(p), key)];
        }
        for (int c = 0; c < 256; ++c) {
            int n = count[c];
            if (n == 0) continue;
            ++report.pairCountNthKey[n];
            ++report.nonEmptyPairs;
            if (n >= 2) ++report.multiKeyPairs;
            if (n > report.maxKeys) {
                report.maxKeys = n;
                report.maxP = static_cast<uint8_t>(p);
                report.maxC = static_cast<uint8_t>(c);
            }
        }
    }
    return report;
}

// ---------------------------------------------------------------------------
// 报告格式化
// ---------------------------------------------------------------------------
namespace {

std::string bits8(uint8_t v) { return toBinaryString(v, 8); }

} // namespace

std::string formatKeyEquivalence(const KeyEquivalenceReport& r) {
    std::ostringstream os;
    os << "① 密钥等价类分析（Keygen 输出去重）\n";
    os << "   密钥总数            : 1024\n";
    os << "   不同 (k1,k2) 子密钥对: " << r.distinctSubKeyPairs << "\n";
    os << "   等价类规模范围      : " << r.minClassSize << " ~ " << r.maxClassSize << "\n";
    os << "   => 平均每个子密钥对对应 " << (1024.0 / r.distinctSubKeyPairs)
       << " 个密钥，" << (1024 - r.distinctSubKeyPairs) << " 个密钥与其他密钥完全等价。\n";
    os << "\n   等价类示例（前 4 类）:\n";
    int shown = 0;
    for (const auto& cls : r.classes) {
        if (shown++ >= 4) break;
        os << "   k1=" << bits8(cls.k1) << ", k2=" << bits8(cls.k2)
           << "  等价密钥 " << cls.keys.size() << " 个: ";
        for (size_t i = 0; i < cls.keys.size(); ++i) {
            os << toBinaryString(cls.keys[i], 10);
            if (i + 1 < cls.keys.size()) os << ", ";
        }
        os << "\n";
    }
    return os.str();
}

std::string formatPlaintextCollision(const PlaintextCollisionReport& r) {
    std::ostringstream os;
    os << "② 明文维度碰撞检测（每个明文枚举 1024 个密钥）\n";
    os << "   存在碰撞的明文个数  : " << r.plaintextsWithCollision << " / 256\n";
    os << "   碰撞密钥对总数      : " << r.totalCollisionPairs
       << "  （在所有明文的 1024^2 个密钥对中）\n";
    os << "   单 (P,C) 最大密钥数 : " << r.maxMultiplicity << "\n";
    os << "   最大案例            : P=" << bits8(r.exampleP)
       << ", C=" << bits8(r.exampleC)
       << "，匹配密钥 " << r.exampleKeys.size() << " 个\n";
    os << "   该案例全部密钥      : ";
    for (size_t i = 0; i < r.exampleKeys.size(); ++i) {
        os << toBinaryString(r.exampleKeys[i], 10);
        if (i + 1 < r.exampleKeys.size()) os << ", ";
    }
    os << "\n";
    return os.str();
}

std::string formatCipherProfile(const CipherProfileReport& r) {
    std::ostringstream os;
    os << "③ 全空间 (P,C) 匹配密钥数分布\n";
    os << "   非空 (P,C) 对数     : " << r.nonEmptyPairs << " / 65536\n";
    os << "   匹配密钥 ≥ 2 的对数 : " << r.multiKeyPairs
       << "  (" << (100.0 * r.multiKeyPairs / r.nonEmptyPairs) << "%)\n";
    os << "   最大匹配密钥数      : " << r.maxKeys
       << "  (P=" << bits8(r.maxP) << ", C=" << bits8(r.maxC) << ")\n";
    os << "\n   匹配密钥个数 n  ->  (P,C) 对数量:\n";
    for (size_t n = 1; n < r.pairCountNthKey.size(); ++n) {
        if (r.pairCountNthKey[n] == 0) continue;
        os << "     n=" << n << " : " << r.pairCountNthKey[n] << "\n";
    }
    return os.str();
}

} // namespace sdes
