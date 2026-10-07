#ifndef SDES_BRUTEFORCE_MT_H
#define SDES_BRUTEFORCE_MT_H

#include <cstdint>
#include <utility>
#include <vector>

#include "sdes.h"

// ---------------------------------------------------------------------------
// 第 4 关：多线程暴力破解模块
//
// 密钥空间只有 2^10 = 1024，把 [0, 1024) 均分给 N 个线程并行遍历：
//   每个线程独立筛选“满足全部 (P,C) 约束”的密钥 -> 汇总 -> 排序
// 同时统计墙钟耗时与尝试次数，便于在报告中给出定量的破解性能结论。
//
// 设计说明：
//   * 线程数默认取 min(硬件并发数, 16)：密钥空间太小，线程过多只会
//     增加线程创建/调度开销，反而拖慢总耗时。
//   * rounds 参数用于 GUI/控制台的“批量压力测试”——把整个密钥空间
//     连续遍历 rounds 遍，把毫秒级耗时放大到秒级，便于观察与录屏。
// ---------------------------------------------------------------------------
namespace sdes {

struct BruteForceResult {
    std::vector<uint16_t> keys;    // 全部匹配的候选密钥（升序）
    double    elapsedMs   = 0.0;   // 墙钟耗时（毫秒）
    int       threadCount = 0;     // 实际使用的线程数
    long long attempts    = 0;     // 实际尝试的密钥个数 = 1024 × rounds
    long long keyMatches  = 0;     // 匹配次数 = keys.size() × rounds
    double    keysPerSecond = 0.0; // 吞吐：每秒尝试的密钥个数
};

// threadCount 传 0 表示自动（min(硬件并发数, 16)）；rounds 为密钥空间遍历遍数
BruteForceResult bruteForceParallel(
    const std::vector<std::pair<uint8_t, uint8_t>>& pairs,
    int threadCount = 0,
    int rounds = 1);

// 便捷重载：直接用单个 (明文, 密文) 对调用
BruteForceResult bruteForceParallel(uint8_t plaintext, uint8_t ciphertext,
                                    int threadCount = 0, int rounds = 1);

} // namespace sdes

#endif // SDES_BRUTEFORCE_MT_H
