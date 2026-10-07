#include "bruteforce_mt.h"

#include <algorithm>
#include <chrono>
#include <thread>

namespace sdes {

BruteForceResult bruteForceParallel(
        const std::vector<std::pair<uint8_t, uint8_t>>& pairs,
        int threadCount, int rounds) {
    BruteForceResult result;
    if (pairs.empty() || rounds < 1) return result;

    // ---- 1. 确定线程数 ----
    int n = threadCount;
    if (n <= 0) {
        unsigned hw = std::thread::hardware_concurrency();
        n = static_cast<int>(hw == 0 ? 1 : hw);
    }
    if (n > 16) n = 16;   // 密钥空间仅 1024，线程过多只会增加调度开销
    if (n < 1) n = 1;
    result.threadCount = n;

    // ---- 2. 把 [0,1024) 均分给各线程 ----
    struct Chunk {
        uint16_t begin = 0;   // 起点（含）
        uint16_t end   = 0;   // 终点（不含）
        std::vector<uint16_t> matched;
    };
    std::vector<Chunk> chunks(static_cast<size_t>(n));
    for (int i = 0; i < n; ++i) {
        chunks[static_cast<size_t>(i)].begin = static_cast<uint16_t>(1024 * i / n);
        chunks[static_cast<size_t>(i)].end   = static_cast<uint16_t>(1024 * (i + 1) / n);
    }

    // ---- 3. 并行枚举（计时覆盖创建工作线程之后到全部 join 之间） ----
    auto t0 = std::chrono::high_resolution_clock::now();

    std::vector<std::thread> workers;
    workers.reserve(static_cast<size_t>(n));
    for (int i = 0; i < n; ++i) {
        workers.emplace_back([&chunks, &pairs, i, rounds]() {
            Chunk& c = chunks[static_cast<size_t>(i)];
            for (int r = 0; r < rounds; ++r) {
                for (uint16_t key = c.begin; key < c.end; ++key) {
                    bool ok = true;
                    for (const auto& pc : pairs) {
                        if (encrypt(pc.first, key) != pc.second) {
                            ok = false;
                            break;
                        }
                    }
                    // 只在第 1 轮记录结果，避免重复写入
                    if (ok && r == 0) c.matched.push_back(key);
                }
            }
        });
    }
    for (auto& w : workers) w.join();

    auto t1 = std::chrono::high_resolution_clock::now();

    // ---- 4. 汇总与统计 ----
    for (const auto& c : chunks) {
        result.keys.insert(result.keys.end(), c.matched.begin(), c.matched.end());
    }
    std::sort(result.keys.begin(), result.keys.end());

    result.elapsedMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
    result.attempts  = static_cast<long long>(1024) * rounds;
    result.keyMatches = static_cast<long long>(result.keys.size()) * rounds;
    result.keysPerSecond = result.elapsedMs > 0.0
        ? static_cast<double>(result.attempts) / (result.elapsedMs / 1000.0)
        : 0.0;
    return result;
}

BruteForceResult bruteForceParallel(uint8_t plaintext, uint8_t ciphertext,
                                    int threadCount, int rounds) {
    std::vector<std::pair<uint8_t, uint8_t>> pairs{{plaintext, ciphertext}};
    return bruteForceParallel(pairs, threadCount, rounds);
}

} // namespace sdes
