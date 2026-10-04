// =============================================================================
//  brute_force.cpp
//  第 4 关：多线程暴力破解的实现
// =============================================================================

#include "sdes/brute_force.hpp"

#include <algorithm>
#include <atomic>
#include <mutex>
#include <stdexcept>
#include <thread>

#include "sdes/cipher.hpp"

namespace sdes {
namespace {

/// 每个线程一次领取的密钥个数。取 16 是为了在「负载均衡」与「原子操作开销」
/// 之间折中：任务太大会出现线程间不均，太小则原子操作成为瓶颈。
constexpr std::size_t kKeyChunkSize = 16;

/// 判断某个密钥能否同时满足全部已知明密文对。
bool keyMatchesAllPairs(const Block10& key, const std::vector<KnownPair>& pairs,
                        KeyScheduleMode keyScheduleMode) {
    const Cipher cipher(key, SBoxSet::homework(), keyScheduleMode);
    for (const KnownPair& pair : pairs) {
        if (cipher.encrypt(pair.plaintext) != pair.ciphertext) {
            return false;
        }
    }
    return true;
}

}  // namespace

// -----------------------------------------------------------------------------
//  BruteForceStats
// -----------------------------------------------------------------------------

double BruteForceStats::elapsedSeconds() const {
    return std::chrono::duration<double>(totalDuration).count();
}

double BruteForceStats::elapsedMilliseconds() const {
    return elapsedSeconds() * 1000.0;
}

double BruteForceStats::elapsedMicroseconds() const {
    return elapsedSeconds() * 1'000'000.0;
}

double BruteForceStats::keysPerSecond() const {
    const double seconds = elapsedSeconds();
    if (seconds <= 0.0) {
        return 0.0;
    }
    return static_cast<double>(keysTested) / seconds;
}

// -----------------------------------------------------------------------------
//  多线程暴力破解
// -----------------------------------------------------------------------------

BruteForceResult bruteForceKey(const std::vector<KnownPair>& pairs, BruteForceOptions options) {
    if (pairs.empty()) {
        throw std::invalid_argument("bruteForceKey: 至少需要一对已知的明密文才能破解。");
    }

    unsigned workerThreads = options.workerThreads;
    if (workerThreads == 0) {
        workerThreads = std::thread::hardware_concurrency();
        if (workerThreads == 0) {
            workerThreads = 1;  // 平台无法报告并发度时退化为单线程
        }
    }
    // 线程数多于密钥块数没有意义，反而白白付出线程创建开销。
    const std::size_t chunkCount = (kKeySpaceSize + kKeyChunkSize - 1) / kKeyChunkSize;
    workerThreads = static_cast<unsigned>(std::min<std::size_t>(workerThreads, chunkCount));

    BruteForceResult result;
    result.stats.keySpaceSize = kKeySpaceSize;
    result.stats.workerThreads = workerThreads;
    result.stats.startedAt = std::chrono::system_clock::now();

    // 把密钥空间切成固定大小的块，线程用原子计数器「抢块」，天然负载均衡。
    std::atomic<std::size_t> nextChunk{0};
    std::atomic<std::size_t> testedCount{0};
    std::mutex candidateMutex;

    const std::chrono::steady_clock::time_point startedAt = std::chrono::steady_clock::now();

    const auto workerBody = [&]() {
        for (;;) {
            const std::size_t chunkIndex = nextChunk.fetch_add(1, std::memory_order_relaxed);
            if (chunkIndex >= chunkCount) {
                return;  // 所有块都被领完了
            }

            const std::size_t begin = chunkIndex * kKeyChunkSize;
            const std::size_t end = std::min(begin + kKeyChunkSize, kKeySpaceSize);

            for (std::size_t raw = begin; raw < end; ++raw) {
                const Block10 key = Block10::fromUint(static_cast<std::uint32_t>(raw));
                if (keyMatchesAllPairs(key, pairs, options.keyScheduleMode)) {
                    std::lock_guard<std::mutex> guard(candidateMutex);
                    result.candidateKeys.push_back(key);
                }
            }

            testedCount.fetch_add(end - begin, std::memory_order_relaxed);
            if (options.onProgress) {
                options.onProgress(testedCount.load(std::memory_order_relaxed), kKeySpaceSize);
            }
        }
    };

    {
        std::vector<std::thread> workers;
        workers.reserve(workerThreads);
        for (unsigned index = 0; index < workerThreads; ++index) {
            workers.emplace_back(workerBody);
        }
        for (std::thread& worker : workers) {
            worker.join();
        }
    }

    const std::chrono::steady_clock::time_point finishedAt = std::chrono::steady_clock::now();
    result.stats.totalDuration = finishedAt - startedAt;
    result.stats.keysTested = testedCount.load();
    result.stats.finishedAt = std::chrono::system_clock::now();

    std::sort(result.candidateKeys.begin(), result.candidateKeys.end());
    return result;
}

// -----------------------------------------------------------------------------
//  单线程对照版本
// -----------------------------------------------------------------------------

BruteForceResult bruteForceKeySingleThreaded(const std::vector<KnownPair>& pairs,
                                             KeyScheduleMode keyScheduleMode) {
    if (pairs.empty()) {
        throw std::invalid_argument("bruteForceKeySingleThreaded: 至少需要一对已知的明密文。");
    }

    BruteForceResult result;
    result.stats.keySpaceSize = kKeySpaceSize;
    result.stats.workerThreads = 1;
    result.stats.startedAt = std::chrono::system_clock::now();

    const std::chrono::steady_clock::time_point startedAt = std::chrono::steady_clock::now();
    for (std::size_t raw = 0; raw < kKeySpaceSize; ++raw) {
        const Block10 key = Block10::fromUint(static_cast<std::uint32_t>(raw));
        if (keyMatchesAllPairs(key, pairs, keyScheduleMode)) {
            result.candidateKeys.push_back(key);
        }
        ++result.stats.keysTested;
    }
    const std::chrono::steady_clock::time_point finishedAt = std::chrono::steady_clock::now();

    result.stats.totalDuration = finishedAt - startedAt;
    result.stats.finishedAt = std::chrono::system_clock::now();
    return result;
}

}  // namespace sdes
