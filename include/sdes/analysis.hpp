// =============================================================================
//  analysis.hpp
//  第 5 关：封闭测试 —— 密钥空间的结构分析
//
//  要回答两个问题：
//      问题 A：对某个随机选出的明密文对，是否可能有不止一个密钥？
//      问题 B：对任意固定的明文分组，是否会出现不同密钥加密得到相同密文？
//
//  做法是干脆把整个密钥空间（1024 个密钥）跑一遍，把「密钥 -> 加密映射」
//  这件事完全枚举出来：密钥空间只有 1024，明文空间只有 256，可以穷举证明。
// =============================================================================

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

#include "sdes/bit_block.hpp"
#include "sdes/key_schedule.hpp"

namespace sdes {

/// 固定明文 P 时，「密文 -> 能产出该密文的全部密钥」的映射表。
using CiphertextKeyMap = std::map<Block8, std::vector<Block10>>;

/// 固定明文，穷举全部 1024 个密钥，得到密文到密钥集合的完整映射。
CiphertextKeyMap groupKeysByCiphertext(Block8 plaintext,
                                       KeyScheduleMode keyScheduleMode = kDefaultKeyScheduleMode);

/// 对单个明文分组的密钥空间统计。
struct PlaintextAnalysis {
    Block8 plaintext;
    std::size_t keyCount = 0;               ///< 参与统计的密钥总数（1024）
    std::size_t distinctCiphertexts = 0;    ///< 实际出现的不同密文个数
    std::size_t singleKeyCiphertexts = 0;   ///< 只对应唯一密钥的密文个数
    std::size_t collidingCiphertexts = 0;   ///< 对应 >= 2 个密钥的密文个数
    std::size_t keysInCollisions = 0;       ///< 落在碰撞中的密钥个数
    std::size_t maxKeysPerCiphertext = 0;   ///< 单个密文最多能被多少个密钥产出
    double averageKeysPerCiphertext = 0.0;  ///< 平均每个密文对应多少密钥
    int maxAchievableBits = 0;              ///< 以 2 为底取对数，说明该明文下密文的有效位数
    bool coversWholeCipherSpace = false;    ///< 是否覆盖全部 256 种可能密文
    Block8 mostCommonCiphertext;            ///< 最常见（碰撞最严重）的密文
    std::vector<Block10> mostCommonKeys;    ///< 产出该密文的全部密钥
    double elapsedMs = 0.0;
};

/// 对指定明文做完整统计。
PlaintextAnalysis analysePlaintext(Block8 plaintext,
                                   KeyScheduleMode keyScheduleMode = kDefaultKeyScheduleMode);

/// 一个等价密钥类：类中的所有密钥对**任意**明文分组都产生完全相同的密文，
/// 因此从外部观测上无法区分它们。
struct EquivalentKeyClass {
    std::vector<Block10> keys;
};

/// 穷举 1024 个密钥，按「对全部 256 种明文的加密结果」给密钥分组，
/// 得到全部等价密钥类（按类大小降序排列）。
std::vector<EquivalentKeyClass> findEquivalentKeyClasses(
    KeyScheduleMode keyScheduleMode = kDefaultKeyScheduleMode);

/// 整个密钥空间的总体分析结果。
struct KeySpaceAnalysis {
    std::size_t keySpaceSize = 0;          ///< 1024
    std::size_t distinctRoundKeyPairs = 0; ///< 两把轮密钥 (k1, k2) 的不同组合数
    std::size_t distinctPermutations = 0;  ///< 真正互不相同的加密映射个数（等价类个数）
    std::size_t trivialClassCount = 0;     ///< 只含单个密钥的等价类个数
    std::size_t nontrivialClassCount = 0;  ///< 含 >= 2 个密钥的等价类个数
    std::size_t largestClassSize = 0;
    double averageClassSize = 0.0;
    std::size_t effectiveKeyBits = 0;      ///< 实际有效密钥位数 = log2(distinctPermutations) 向上取整
    double elapsedMs = 0.0;
};

/// 计算密钥空间的总体结构，并把等价类通过 classesOut 返回。
KeySpaceAnalysis analyseKeySpace(std::vector<EquivalentKeyClass>& classesOut,
                                 KeyScheduleMode keyScheduleMode = kDefaultKeyScheduleMode);

}  // namespace sdes
