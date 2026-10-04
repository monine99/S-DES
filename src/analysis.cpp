// =============================================================================
//  analysis.cpp
//  第 5 关：密钥空间结构分析的实现
// =============================================================================

#include "sdes/analysis.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <set>

#include "sdes/brute_force.hpp"
#include "sdes/cipher.hpp"

namespace sdes {
namespace {

/// 明文空间大小：8 bit 分组 -> 256 种。
constexpr std::size_t kPlaintextSpaceSize = std::size_t{1} << 8;

/// 一个密钥的「行为指纹」：它对全部 256 个明文分组加密得到的 256 个密文字节。
/// 两个密钥的指纹相同 <=> 这两个密钥完全等价。
using KeyFingerprint = std::array<std::uint8_t, kPlaintextSpaceSize>;

/// 计算某个密钥的完整行为指纹。
KeyFingerprint computeFingerprint(const Block10& key, KeyScheduleMode keyScheduleMode) {
    const Cipher cipher(key, SBoxSet::homework(), keyScheduleMode);
    KeyFingerprint fingerprint{};
    for (std::size_t plainValue = 0; plainValue < kPlaintextSpaceSize; ++plainValue) {
        const Block8 plaintext = Block8::fromUint(static_cast<std::uint32_t>(plainValue));
        fingerprint[plainValue] = byteFromBlock(cipher.encrypt(plaintext));
    }
    return fingerprint;
}

}  // namespace

// -----------------------------------------------------------------------------
//  单明文统计
// -----------------------------------------------------------------------------

CiphertextKeyMap groupKeysByCiphertext(Block8 plaintext, KeyScheduleMode keyScheduleMode) {
    CiphertextKeyMap mapping;
    for (std::size_t raw = 0; raw < kKeySpaceSize; ++raw) {
        const Block10 key = Block10::fromUint(static_cast<std::uint32_t>(raw));
        const Cipher cipher(key, SBoxSet::homework(), keyScheduleMode);
        mapping[cipher.encrypt(plaintext)].push_back(key);
    }
    return mapping;
}

PlaintextAnalysis analysePlaintext(Block8 plaintext, KeyScheduleMode keyScheduleMode) {
    const std::chrono::steady_clock::time_point startedAt = std::chrono::steady_clock::now();

    const CiphertextKeyMap mapping = groupKeysByCiphertext(plaintext, keyScheduleMode);

    PlaintextAnalysis analysis;
    analysis.plaintext = plaintext;
    analysis.keyCount = kKeySpaceSize;
    analysis.distinctCiphertexts = mapping.size();

    for (const auto& entry : mapping) {
        const std::size_t keysForThisCiphertext = entry.second.size();
        if (keysForThisCiphertext == 1) {
            ++analysis.singleKeyCiphertexts;
        } else {
            ++analysis.collidingCiphertexts;
            analysis.keysInCollisions += keysForThisCiphertext;
        }
        if (keysForThisCiphertext > analysis.maxKeysPerCiphertext) {
            analysis.maxKeysPerCiphertext = keysForThisCiphertext;
            analysis.mostCommonCiphertext = entry.first;
            analysis.mostCommonKeys = entry.second;
        }
    }

    analysis.averageKeysPerCiphertext =
        static_cast<double>(analysis.keyCount) / static_cast<double>(analysis.distinctCiphertexts);
    analysis.maxAchievableBits =
        static_cast<int>(std::floor(std::log2(static_cast<double>(analysis.distinctCiphertexts))));
    analysis.coversWholeCipherSpace = (analysis.distinctCiphertexts == kPlaintextSpaceSize);

    const std::chrono::steady_clock::time_point finishedAt = std::chrono::steady_clock::now();
    analysis.elapsedMs = std::chrono::duration<double, std::milli>(finishedAt - startedAt).count();
    return analysis;
}

// -----------------------------------------------------------------------------
//  等价密钥类
// -----------------------------------------------------------------------------

std::vector<EquivalentKeyClass> findEquivalentKeyClasses(KeyScheduleMode keyScheduleMode) {
    std::map<KeyFingerprint, std::vector<Block10>> groups;

    for (std::size_t raw = 0; raw < kKeySpaceSize; ++raw) {
        const Block10 key = Block10::fromUint(static_cast<std::uint32_t>(raw));
        groups[computeFingerprint(key, keyScheduleMode)].push_back(key);  // raw 递增，组内天然有序
    }

    std::vector<EquivalentKeyClass> classes;
    classes.reserve(groups.size());
    for (auto& entry : groups) {
        classes.push_back(EquivalentKeyClass{std::move(entry.second)});
    }

    // 类大的排前面，便于观察密钥空间的塌缩情况。
    std::sort(classes.begin(), classes.end(),
              [](const EquivalentKeyClass& left, const EquivalentKeyClass& right) {
                  if (left.keys.size() != right.keys.size()) {
                      return left.keys.size() > right.keys.size();
                  }
                  return left.keys.front() < right.keys.front();
              });
    return classes;
}

// -----------------------------------------------------------------------------
//  密钥空间总体分析
// -----------------------------------------------------------------------------

KeySpaceAnalysis analyseKeySpace(std::vector<EquivalentKeyClass>& classesOut,
                                 KeyScheduleMode keyScheduleMode) {
    const std::chrono::steady_clock::time_point startedAt = std::chrono::steady_clock::now();

    // 先看 (k1, k2) 有多少种不同组合。密钥扩展 P10/P8 会丢弃 2 bit 信息，
    // 因此 1024 个密钥映射到的轮密钥组合必然少于 1024，这正是等价密钥的来源。
    std::set<std::uint32_t> distinctRoundKeyPairs;
    for (std::size_t raw = 0; raw < kKeySpaceSize; ++raw) {
        const Block10 key = Block10::fromUint(static_cast<std::uint32_t>(raw));
        const RoundKeys roundKeys = deriveRoundKeys(key, keyScheduleMode);
        const std::uint32_t packedRoundKeys =
            (static_cast<std::uint32_t>(roundKeys.k1.toUint()) << 8) | roundKeys.k2.toUint();
        distinctRoundKeyPairs.insert(packedRoundKeys);
    }

    classesOut = findEquivalentKeyClasses(keyScheduleMode);

    KeySpaceAnalysis analysis;
    analysis.keySpaceSize = kKeySpaceSize;
    analysis.distinctRoundKeyPairs = distinctRoundKeyPairs.size();
    analysis.distinctPermutations = classesOut.size();

    for (const EquivalentKeyClass& keyClass : classesOut) {
        if (keyClass.keys.size() == 1) {
            ++analysis.trivialClassCount;
        } else {
            ++analysis.nontrivialClassCount;
        }
        analysis.largestClassSize = std::max(analysis.largestClassSize, keyClass.keys.size());
    }
    analysis.averageClassSize =
        static_cast<double>(analysis.keySpaceSize) / static_cast<double>(analysis.distinctPermutations);

    // 有效密钥位数：以 2 为底向上取整，说明实际安全强度。
    std::size_t effectiveBits = 0;
    while ((std::size_t{1} << effectiveBits) < analysis.distinctPermutations) {
        ++effectiveBits;
    }
    analysis.effectiveKeyBits = effectiveBits;

    const std::chrono::steady_clock::time_point finishedAt = std::chrono::steady_clock::now();
    analysis.elapsedMs = std::chrono::duration<double, std::milli>(finishedAt - startedAt).count();
    return analysis;
}

}  // namespace sdes
