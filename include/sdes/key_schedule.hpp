// =============================================================================
//  key_schedule.hpp
//  S-DES 密钥扩展：由 10 bit 主密钥导出两把 8 bit 轮密钥 k1、k2
//
//      作业公式： k_i = P8( Shift^i( P10(K) ) ) ,  i = 1, 2
//
//  ⚠ 这条公式存在两种读法，两者给出的 k2 不同，进而密文不同。为便于和同学
//    交叉测试（第 2 关），这里把两种读法都实现出来，可随时切换：
//
//      读法 A —— TextbookProgressive（默认，标准 S-DES 流程）
//          k1 = P8( LS-1(P10(K)) )
//          k2 = P8( LS-2(LS-1(P10(K))) )     ← 在 k1 的状态上再移 2 位，累计 3 位
//          这正是 Schneier《Applied Cryptography》里 S-DES 结构图的画法：
//          第二个 LS 的箭头从第一个 LS 的输出接出去。
//          当 K = 1010000010 时：k1 = 10100100，k2 = 01000011（公认标准值）。
//
//      读法 B —— LiteralFormula（严格照抄公式字面）
//          k1 = P8( LS-1(P10(K)) )
//          k2 = P8( LS-2(P10(K)) )           ← 直接对 P10(K) 各半移 2 位
//          当 K = 1010000010 时：k1 = 10100100，k2 = 10010010。
//
//      两种读法的 k1 完全相同，只有 k2 不同。
// =============================================================================

#pragma once

#include "sdes/bit_block.hpp"

namespace sdes {

/// 密钥扩展的读法。
enum class KeyScheduleMode {
    /// 教材 / 标准 S-DES 流程：k2 在 k1 的状态上再左移 2 位（累计 3 位）。
    TextbookProgressive,
    /// 严格照抄作业公式：k2 对 P10(K) 各半左移 2 位。
    LiteralFormula,
};

/// 工程默认采用的读法。
inline constexpr KeyScheduleMode kDefaultKeyScheduleMode = KeyScheduleMode::TextbookProgressive;

/// 两把轮密钥。k1 用于第一轮，k2 用于第二轮。
struct RoundKeys {
    Block8 k1;
    Block8 k2;
};

/// 由 10 bit 主密钥导出轮密钥。
RoundKeys deriveRoundKeys(const Block10& masterKey, KeyScheduleMode mode = kDefaultKeyScheduleMode);

/// 逐步骤版的密钥扩展，便于界面展示与教学讲解。
struct KeyScheduleTrace {
    Block10 masterKey;      ///< 原始密钥 K
    KeyScheduleMode mode;   ///< 采用的读法

    Block10 afterP10;       ///< P10(K)

    Block5 leftAfterShift1;   ///< 左半段左移 1 位
    Block5 rightAfterShift1;  ///< 右半段左移 1 位
    Block10 afterShift1;      ///< 供 k1 使用的 10 bit 串

    Block5 leftAfterShift2;   ///< 左半段再左移 2 位（读法 A）或直接左移 2 位（读法 B）
    Block5 rightAfterShift2;  ///< 右半段同上
    Block10 afterShift2;      ///< 供 k2 使用的 10 bit 串

    Block8 k1;                ///< P8(afterShift1)
    Block8 k2;                ///< P8(afterShift2)
};

/// 带中间过程记录的密钥扩展。
KeyScheduleTrace traceKeySchedule(const Block10& masterKey,
                                  KeyScheduleMode mode = kDefaultKeyScheduleMode);

/// 供文档与界面使用的读法名称。
const char* describeKeyScheduleMode(KeyScheduleMode mode) noexcept;

}  // namespace sdes
