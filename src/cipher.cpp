// =============================================================================
//  cipher.cpp
//  S-DES 加解密的实现
// =============================================================================

#include "sdes/cipher.hpp"

namespace sdes {
namespace {

/// 把 0..3 的整数写成 2 bit 位串。
Block2 twoBitBlock(int value) noexcept {
    Block2 block;
    block.set(0, (value & 0b10) != 0);
    block.set(1, (value & 0b01) != 0);
    return block;
}

}  // namespace

// -----------------------------------------------------------------------------
//  S 盒
// -----------------------------------------------------------------------------

Block2 applySBox(const Block4& input, const tables::SBoxTable& sBox) {
    // 行号 = 第 1 位与第 4 位拼成的两位二进制数；列号 = 第 2 位与第 3 位。
    const int row = (input.at(0) ? 2 : 0) + (input.at(3) ? 1 : 0);
    const int column = (input.at(1) ? 2 : 0) + (input.at(2) ? 1 : 0);
    return twoBitBlock(sBox[static_cast<std::size_t>(row)][static_cast<std::size_t>(column)]);
}

// -----------------------------------------------------------------------------
//  轮函数
// -----------------------------------------------------------------------------

Block4 Cipher::substituteThroughSBoxes(const Block8& mixed, const SBoxSet& sBoxes) {
    const auto [highHalf, lowHalf] = mixed.split();  // 各 4 bit
    const Block2 substitutedHigh = applySBox(highHalf, sBoxes.s1());
    const Block2 substitutedLow = applySBox(lowHalf, sBoxes.s2());
    return Block4::concat(substitutedHigh, substitutedLow);
}

Block4 Cipher::feistelFunction(const Block4& rightHalf, const Block8& roundKey, const SBoxSet& sBoxes) {
    const Block8 expanded = permute(rightHalf, tables::kEP);  // 4 -> 8 bit
    const Block8 mixed = expanded ^ roundKey;                 // 与轮密钥异或
    const Block4 substituted = substituteThroughSBoxes(mixed, sBoxes);
    return permute(substituted, tables::kSP);  // SP 置换，4 -> 4 bit
}

Block8 Cipher::swapHalves(const Block8& block) noexcept {
    const auto [left, right] = block.split();
    return Block8::concat(right, left);
}

Block8 Cipher::feistelRound(const Block8& block, const Block8& roundKey, const SBoxSet& sBoxes) {
    const auto [left, right] = block.split();
    const Block4 functionOutput = feistelFunction(right, roundKey, sBoxes);
    return Block8::concat(left ^ functionOutput, right);
}

// -----------------------------------------------------------------------------
//  构造
// -----------------------------------------------------------------------------

Cipher::Cipher(Block10 masterKey, SBoxSet sBoxes, KeyScheduleMode keyScheduleMode)
    : masterKey_(masterKey),
      sBoxes_(sBoxes),
      keyScheduleMode_(keyScheduleMode),
      roundKeys_(deriveRoundKeys(masterKey, keyScheduleMode)) {}

// -----------------------------------------------------------------------------
//  加解密
// -----------------------------------------------------------------------------

Block8 Cipher::encrypt(Block8 plaintext) const {
    const Block8 afterIP = permute(plaintext, tables::kIP);
    const Block8 afterRound1 = feistelRound(afterIP, roundKeys_.k1, sBoxes_);
    const Block8 afterSwap = swapHalves(afterRound1);
    const Block8 afterRound2 = feistelRound(afterSwap, roundKeys_.k2, sBoxes_);
    return permute(afterRound2, tables::kIPInverse);
}

Block8 Cipher::decrypt(Block8 ciphertext) const {
    // 解密与加密的唯一区别：两把轮密钥的使用顺序颠倒。
    const Block8 afterIP = permute(ciphertext, tables::kIP);
    const Block8 afterRound1 = feistelRound(afterIP, roundKeys_.k2, sBoxes_);
    const Block8 afterSwap = swapHalves(afterRound1);
    const Block8 afterRound2 = feistelRound(afterSwap, roundKeys_.k1, sBoxes_);
    return permute(afterRound2, tables::kIPInverse);
}

// -----------------------------------------------------------------------------
//  带中间过程的版本
// -----------------------------------------------------------------------------

CipherTrace Cipher::traceEncrypt(Block8 plaintext) const {
    CipherTrace trace;
    trace.input = plaintext;
    trace.afterIP = permute(plaintext, tables::kIP);

    const auto [left1, right1] = trace.afterIP.split();
    trace.leftBeforeRound1 = left1;
    trace.rightBeforeRound1 = right1;
    trace.firstRoundKey = roundKeys_.k1;
    trace.afterFeistel1 = feistelFunction(right1, roundKeys_.k1, sBoxes_);
    trace.afterRound1 = feistelRound(trace.afterIP, roundKeys_.k1, sBoxes_);

    trace.afterSwap = swapHalves(trace.afterRound1);
    const auto [left2, right2] = trace.afterSwap.split();
    trace.leftBeforeRound2 = left2;
    trace.rightBeforeRound2 = right2;
    trace.secondRoundKey = roundKeys_.k2;
    trace.afterFeistel2 = feistelFunction(right2, roundKeys_.k2, sBoxes_);
    trace.afterRound2 = feistelRound(trace.afterSwap, roundKeys_.k2, sBoxes_);

    trace.output = permute(trace.afterRound2, tables::kIPInverse);
    return trace;
}

CipherTrace Cipher::traceDecrypt(Block8 ciphertext) const {
    CipherTrace trace;
    trace.input = ciphertext;
    trace.afterIP = permute(ciphertext, tables::kIP);

    const auto [left1, right1] = trace.afterIP.split();
    trace.leftBeforeRound1 = left1;
    trace.rightBeforeRound1 = right1;
    trace.firstRoundKey = roundKeys_.k2;  // 解密时第一轮用 k2
    trace.afterFeistel1 = feistelFunction(right1, roundKeys_.k2, sBoxes_);
    trace.afterRound1 = feistelRound(trace.afterIP, roundKeys_.k2, sBoxes_);

    trace.afterSwap = swapHalves(trace.afterRound1);
    const auto [left2, right2] = trace.afterSwap.split();
    trace.leftBeforeRound2 = left2;
    trace.rightBeforeRound2 = right2;
    trace.secondRoundKey = roundKeys_.k1;  // 第二轮用 k1
    trace.afterFeistel2 = feistelFunction(right2, roundKeys_.k1, sBoxes_);
    trace.afterRound2 = feistelRound(trace.afterSwap, roundKeys_.k1, sBoxes_);

    trace.output = permute(trace.afterRound2, tables::kIPInverse);
    return trace;
}

// -----------------------------------------------------------------------------
//  第 3 关：字符串加解密
// -----------------------------------------------------------------------------

std::string Cipher::encryptText(std::string_view plaintext) const {
    std::string ciphertext;
    ciphertext.reserve(plaintext.size());
    for (const char character : plaintext) {
        const Block8 plainBlock = blockFromByte(static_cast<unsigned char>(character));
        ciphertext.push_back(static_cast<char>(byteFromBlock(encrypt(plainBlock))));
    }
    return ciphertext;
}

std::string Cipher::decryptText(std::string_view ciphertext) const {
    std::string plaintext;
    plaintext.reserve(ciphertext.size());
    for (const char character : ciphertext) {
        const Block8 cipherBlock = blockFromByte(static_cast<unsigned char>(character));
        plaintext.push_back(static_cast<char>(byteFromBlock(decrypt(cipherBlock))));
    }
    return plaintext;
}

}  // namespace sdes
