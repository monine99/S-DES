// =============================================================================
//  tables.hpp
//  S-DES 的全部转换装置（P-Box / S-Box）常数表
//
//  表中数字一律是 1-based 的「源位序号」：
//      P10 = (3,5,2,7,4,10,1,9,8,6)  表示输出第 1 位取自输入第 3 位。
//
//  【重要】S 盒有两套：
//      kSBox2        —— 作业（第 5 次课 PPT）指定的版本，第 2、3 行与教材不同，
//                       这是本作业的正式标准，所有加解密默认使用它；
//      kSBox2Textbook—— Schneier《Applied Cryptography》里 S-DES 的原始 S1，
//                       仅用于「算法自检」：用它能复现教材经典测试向量
//                       K=1010000010、P=10010111 -> C=00111000，
//                       从而证明 P-Box / 密钥扩展 / 整体流程的实现没有写错。
// =============================================================================

#pragma once

#include <array>

namespace sdes::tables {

/// S 盒的行列均取 0..3，元素为 2 bit 的替换值（0..3）。
using SBoxTable = std::array<std::array<int, 4>, 4>;

// -----------------------------------------------------------------------------
//  密钥扩展
// -----------------------------------------------------------------------------

/// P10：10 bit 密钥的初始置换。
inline constexpr PermutationTable<10> kP10{3, 5, 2, 7, 4, 10, 1, 9, 8, 6};

/// P8：从置换后的 10 bit 中挑出 8 bit 作为轮密钥。
inline constexpr PermutationTable<8> kP8{6, 3, 7, 4, 8, 5, 10, 9};

/// 左半/右半各循环左移 1 位（Left_Shift^1）与 2 位（Left_Shift^2）。
/// 保留成表的形式，方便与作业给出的定义逐项对照，也用于自检。
inline constexpr PermutationTable<5> kLeftShift1{2, 3, 4, 5, 1};
inline constexpr PermutationTable<5> kLeftShift2{3, 4, 5, 1, 2};

// -----------------------------------------------------------------------------
//  初始置换与最终置换
// -----------------------------------------------------------------------------

/// IP：加密开始时的初始置换。
inline constexpr PermutationTable<8> kIP{2, 6, 3, 1, 4, 8, 5, 7};

/// IP^-1：加密结束时的最终置换。
inline constexpr PermutationTable<8> kIPInverse{4, 1, 3, 5, 7, 2, 8, 6};

// -----------------------------------------------------------------------------
//  轮函数
// -----------------------------------------------------------------------------

/// EP（扩展置换）：把 4 bit 右半扩展成 8 bit，注意其中第 1、4 位被重复使用。
inline constexpr PermutationTable<8> kEP{4, 1, 2, 3, 2, 3, 4, 1};

/// SP（S 盒之后的置换，也称 P4）：把 4 bit 输出打乱。
inline constexpr PermutationTable<4> kSP{2, 4, 3, 1};

/// S1（SBox_1）：S-DES 的两个 S 盒中的第一个。
/// 行由输入的第 1、4 位决定，列由第 2、3 位决定。
inline constexpr SBoxTable kSBox1{{
    {1, 0, 3, 2},
    {3, 2, 1, 0},
    {0, 2, 1, 3},
    {3, 1, 0, 2},
}};

/// S2（SBox_2）：**作业指定版本**，第 2、3 行与教材不同，以此为准。
inline constexpr SBoxTable kSBox2{{
    {0, 1, 2, 3},
    {2, 3, 1, 0},
    {3, 0, 1, 2},
    {2, 1, 0, 3},
}};

/// 教材原始 S1，仅供算法自检使用，不参与正式加解密。
inline constexpr SBoxTable kSBox2Textbook{{
    {0, 1, 2, 3},
    {2, 0, 1, 3},
    {3, 0, 1, 0},
    {2, 1, 0, 3},
}};

}  // namespace sdes::tables

namespace sdes {

/// 一组 S 盒。把「作业版」和「教材版」都封装进来，加解密函数通过参数选择，
/// 这样既能跑作业标准，也能随时用教材向量做自检。
struct SBoxSet {
    const tables::SBoxTable* sBox1 = &tables::kSBox1;
    const tables::SBoxTable* sBox2 = &tables::kSBox2;

    /// 作业（PPT）指定的标准：S1 = SBox_1，S2 = 改动后的 SBox_2。
    static constexpr SBoxSet homework() noexcept { return {&tables::kSBox1, &tables::kSBox2}; }

    /// Schneier 教材原始标准，用于验证实现正确性。
    static constexpr SBoxSet textbook() noexcept {
        return {&tables::kSBox1, &tables::kSBox2Textbook};
    }

    const tables::SBoxTable& s1() const noexcept { return *sBox1; }
    const tables::SBoxTable& s2() const noexcept { return *sBox2; }
};

}  // namespace sdes
