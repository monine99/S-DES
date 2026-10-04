// =============================================================================
//  key_schedule.cpp
//  S-DES 密钥扩展的实现
//
//  两种读法的差别只在「k2 用哪一份 10 bit 串」这一点上，见 key_schedule.hpp 的说明。
// =============================================================================

#include "sdes/key_schedule.hpp"

#include "sdes/tables.hpp"

namespace sdes {

const char* describeKeyScheduleMode(KeyScheduleMode mode) noexcept {
    switch (mode) {
        case KeyScheduleMode::TextbookProgressive:
            return "教材递进式 (k2 在 k1 基础上再左移 2 位)";
        case KeyScheduleMode::LiteralFormula:
            return "公式字面式 (k2 对 P10(K) 直接左移 2 位)";
    }
    return "未知";
}

KeyScheduleTrace traceKeySchedule(const Block10& masterKey, KeyScheduleMode mode) {
    KeyScheduleTrace trace;
    trace.masterKey = masterKey;
    trace.mode = mode;

    // 第一步：P10 置换
    trace.afterP10 = permute(masterKey, tables::kP10);

    // 第二步：切成左右各 5 bit，各自循环左移
    const auto [leftHalf, rightHalf] = trace.afterP10.split();

    trace.leftAfterShift1 = leftHalf.rotateLeft(1);
    trace.rightAfterShift1 = rightHalf.rotateLeft(1);
    trace.afterShift1 = Block10::concat(trace.leftAfterShift1, trace.rightAfterShift1);

    if (mode == KeyScheduleMode::TextbookProgressive) {
        // 读法 A：在已经移过 1 位的状态上再移 2 位
        trace.leftAfterShift2 = trace.leftAfterShift1.rotateLeft(2);
        trace.rightAfterShift2 = trace.rightAfterShift1.rotateLeft(2);
    } else {
        // 读法 B：回到 P10 结果，重新左移 2 位
        trace.leftAfterShift2 = leftHalf.rotateLeft(2);
        trace.rightAfterShift2 = rightHalf.rotateLeft(2);
    }
    trace.afterShift2 = Block10::concat(trace.leftAfterShift2, trace.rightAfterShift2);

    // 第三步：P8 各挑出 8 bit，得到 k1、k2
    trace.k1 = permute(trace.afterShift1, tables::kP8);
    trace.k2 = permute(trace.afterShift2, tables::kP8);
    return trace;
}

RoundKeys deriveRoundKeys(const Block10& masterKey, KeyScheduleMode mode) {
    const KeyScheduleTrace trace = traceKeySchedule(masterKey, mode);
    return RoundKeys{trace.k1, trace.k2};
}

}  // namespace sdes
