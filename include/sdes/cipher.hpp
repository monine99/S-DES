// =============================================================================
//  cipher.hpp
//  S-DES 加解密本体
//
//      加密： C = IP^-1( f_k2( SW( f_k1( IP(P) ) ) ) )
//      解密： P = IP^-1( f_k1( SW( f_k2( IP(C) ) ) ) )
//
//  分组 8 bit，密钥 10 bit。除去 S 盒之外的一切都在这里。
// =============================================================================

#pragma once

#include <string>
#include <string_view>

#include "sdes/bit_block.hpp"
#include "sdes/key_schedule.hpp"
#include "sdes/tables.hpp"

namespace sdes {

/// 一次加密/解密的完整中间状态，供界面展示与教学说明使用。
struct CipherTrace {
    Block8 input;       ///< 输入分组（明文或密文）
    Block8 afterIP;     ///< IP(输入)
    Block4 leftBeforeRound1;   ///< 第一轮输入左半
    Block4 rightBeforeRound1;  ///< 第一轮输入右半
    Block8 firstRoundKey;      ///< 第一轮所用轮密钥
    Block4 afterFeistel1;      ///< f_k1 的输出（4 bit）
    Block8 afterRound1;        ///< 第一轮的完整输出
    Block8 afterSwap;          ///< SW 之后
    Block4 leftBeforeRound2;
    Block4 rightBeforeRound2;
    Block8 secondRoundKey;     ///< 第二轮所用轮密钥
    Block4 afterFeistel2;
    Block8 afterRound2;
    Block8 output;             ///< IP^-1 之后，即最终结果
};

/// S-DES 加解密器。构造时给定 10 bit 密钥，随即完成密钥扩展。
class Cipher {
public:
    /// @param masterKey       10 bit 主密钥
    /// @param sBoxes          S 盒组合，默认是作业指定的标准；传 SBoxSet::textbook() 可用教材向量自检
    /// @param keyScheduleMode 密钥扩展的读法，默认按标准 S-DES 流程，详见 key_schedule.hpp
    explicit Cipher(Block10 masterKey, SBoxSet sBoxes = SBoxSet::homework(),
                    KeyScheduleMode keyScheduleMode = kDefaultKeyScheduleMode);

    /// 加密一个 8 bit 分组。
    Block8 encrypt(Block8 plaintext) const;

    /// 解密一个 8 bit 分组。
    Block8 decrypt(Block8 ciphertext) const;

    /// 带中间过程的加密。
    CipherTrace traceEncrypt(Block8 plaintext) const;

    /// 带中间过程的解密。
    CipherTrace traceDecrypt(Block8 ciphertext) const;

    // -------------------------------------------------------------------------
    //  第 3 关：扩展功能 —— 按 1 字节（8 bit）分组处理任意文本
    // -------------------------------------------------------------------------

    /// 逐字节加密。输出是等长的字节序列，内容可能是乱码，这正是分组密码的直接结果。
    std::string encryptText(std::string_view plaintext) const;

    /// 逐字节解密，是 encryptText 的逆运算。
    std::string decryptText(std::string_view ciphertext) const;

    const Block10& masterKey() const noexcept { return masterKey_; }
    const RoundKeys& roundKeys() const noexcept { return roundKeys_; }
    const SBoxSet& sBoxes() const noexcept { return sBoxes_; }
    KeyScheduleMode keyScheduleMode() const noexcept { return keyScheduleMode_; }

    /// 轮函数 f_k：把 4 bit 右半用 EP 扩展、异或轮密钥、过两个 S 盒、再过 SP。
    static Block4 feistelFunction(const Block4& rightHalf, const Block8& roundKey, const SBoxSet& sBoxes);

    /// 交换左右两个 4 bit 半分组（SW）。
    static Block8 swapHalves(const Block8& block) noexcept;

private:
    /// 一个 Feistel 轮：左半与 f(右半) 异或，右半原样带过。
    static Block8 feistelRound(const Block8& block, const Block8& roundKey, const SBoxSet& sBoxes);

    /// 轮函数内部的一轮：8 bit 轮密钥与 4 bit 输入异或后再过 S 盒。
    static Block4 substituteThroughSBoxes(const Block8& mixed, const SBoxSet& sBoxes);

    Block10 masterKey_;
    SBoxSet sBoxes_;
    KeyScheduleMode keyScheduleMode_;
    RoundKeys roundKeys_;
};

/// 用 S 盒替换 4 bit 输入：行号取第 1、4 位，列号取第 2、3 位，得到 2 bit 输出。
Block2 applySBox(const Block4& input, const tables::SBoxTable& sBox);

}  // namespace sdes
