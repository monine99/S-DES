// =============================================================================
//  brute_force.hpp
//  第 4 关：暴力破解
//
//  密钥只有 10 bit，密钥空间 2^10 = 1024，本可以瞬间跑完。
//  这里仍然按「多线程 + 分块 + 计时」的方式实现，是为了演示在密钥空间
//  更大时该怎么写：把密钥空间切成若干块交给多个线程，用原子计数器抢块。
// =============================================================================

#pragma once

#include <chrono>
#include <cstddef>
#include <functional>
#include <vector>

#include "sdes/bit_block.hpp"
#include "sdes/key_schedule.hpp"

namespace sdes {

/// 一对已知的明密文。
struct KnownPair {
    Block8 plaintext;
    Block8 ciphertext;
};

/// 暴力破解的统计信息（第 4 关要求展示时间戳与耗时）。
struct BruteForceStats {
    std::size_t keysTested = 0;     ///< 实际试过的密钥个数
    std::size_t keySpaceSize = 0;   ///< 密钥空间大小（1024）
    unsigned workerThreads = 0;     ///< 实际使用的线程数
    std::chrono::steady_clock::duration totalDuration{};    ///< 单调时钟测得的真实耗时
    std::chrono::system_clock::time_point startedAt{};      ///< 开始时刻（时间戳）
    std::chrono::system_clock::time_point finishedAt{};     ///< 结束时刻（时间戳）

    double elapsedSeconds() const;
    double elapsedMilliseconds() const;
    double elapsedMicroseconds() const;
    /// 每秒尝试的密钥数，用于说明破解效率。
    double keysPerSecond() const;
};

struct BruteForceResult {
    std::vector<Block10> candidateKeys;  ///< 全部满足已知明密文对的密钥，按数值升序
    BruteForceStats stats;
};

/// 进度回调：(已试密钥数, 密钥空间大小)。会在多个工作线程中被调用，
/// 调用方需自行保证线程安全（Qt 侧请用队列连接）。
using BruteForceProgress = std::function<void(std::size_t tested, std::size_t total)>;

/// 暴力破解的可选参数。
struct BruteForceOptions {
    /// 工作线程数。传 0 表示按 std::thread::hardware_concurrency() 自动决定。
    unsigned workerThreads = 0;
    /// 密钥扩展读法。必须与实际加密该明密文时使用的读法一致，否则一个密钥都找不到。
    KeyScheduleMode keyScheduleMode = kDefaultKeyScheduleMode;
    /// 进度回调，可为空。
    BruteForceProgress onProgress;
};

/// 穷举 0 .. 2^10-1 的全部密钥，返回其中能把每一组明文都加密成对应密文的密钥。
///
/// @param pairs   已知的明密文对，可以有多组；只有全部满足的密钥才会被采纳
/// @param options 线程数、密钥扩展读法、进度回调
/// @throws std::invalid_argument 当 pairs 为空时
BruteForceResult bruteForceKey(const std::vector<KnownPair>& pairs, BruteForceOptions options = {});

/// 密钥空间的规模（2^10）。
inline constexpr std::size_t kKeySpaceSize = std::size_t{1} << 10;

/// 单线程版本的暴力破解，用于与多线程版本对照，验证两者结果一致。
BruteForceResult bruteForceKeySingleThreaded(const std::vector<KnownPair>& pairs,
                                             KeyScheduleMode keyScheduleMode = kDefaultKeyScheduleMode);

}  // namespace sdes
