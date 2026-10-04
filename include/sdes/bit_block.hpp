// =============================================================================
//  bit_block.hpp
//  S-DES（Simplified DES）实现 —— 位串基础类型
//
//  【位序约定】这是整个工程最重要的一条约定：
//      BitBlock 内部的索引 0 表示位串「最左侧」的那一位（最高有效位）。
//      于是置换表（P10 / P8 / IP / EP / SP）中写出的 1-based 序号可以
//      直接映射为 input.at(table[i] - 1)，不会产生「从左数还是从右数」的歧义。
//
//      例：BitBlock<8>::fromString("10010111") 中
//          at(0) == true   // 最左边的 1
//          at(3) == true   // 从左数第 4 位
//          at(6) == true   // 从左数第 7 位
//          at(7) == true   // 最右边的 1
//
//  【长度】编译期常量：分组 8 bit、密钥 10 bit、半分组 4 bit。
//          越界访问由 at() 检查并抛出 std::out_of_range。
// =============================================================================

#pragma once

#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace sdes {

/// 定长位串。N 为位数。
template <std::size_t N>
class BitBlock {
public:
    static constexpr std::size_t kSize = N;

    BitBlock() noexcept { bits_.fill(false); }

    // -------------------------------------------------------------------------
    // 构造
    // -------------------------------------------------------------------------

    /// 从 "1010000010" 这样的二进制串解析。
    /// 允许串长不足 N（在左侧补 0，方便手工输入）；串长超过 N 或含非 0/1 字符则抛出
    /// std::invalid_argument。两端的空白字符会被忽略。
    static BitBlock fromString(std::string_view text) {
        const std::optional<BitBlock> parsed = tryFromString(text);
        if (!parsed.has_value()) {
            throw std::invalid_argument("BitBlock<" + std::to_string(N) + ">::fromString: 无法解析 \"" +
                                        std::string(text) + "\"（只允许 0/1，且长度不得超过 " +
                                        std::to_string(N) + "）");
        }
        return *parsed;
    }

    /// fromString 的非异常版本，解析失败返回 std::nullopt。
    static std::optional<BitBlock> tryFromString(std::string_view text) noexcept {
        // 去掉两端空白
        std::size_t first = 0;
        std::size_t last = text.size();
        while (first < last && std::isspace(static_cast<unsigned char>(text[first])) != 0) {
            ++first;
        }
        while (last > first && std::isspace(static_cast<unsigned char>(text[last - 1])) != 0) {
            --last;
        }
        text = text.substr(first, last - first);

        if (text.size() > N) {
            return std::nullopt;
        }

        BitBlock block;  // 默认全 0
        const std::size_t leftPadding = N - text.size();
        for (std::size_t i = 0; i < text.size(); ++i) {
            const char symbol = text[i];
            if (symbol != '0' && symbol != '1') {
                return std::nullopt;
            }
            block.bits_[leftPadding + i] = (symbol == '1');
        }
        return block;
    }

    /// 把整数按「高位对齐」写入位串，例如 fromUint(5) 在 BitBlock<8> 中为 "00000101"。
    static BitBlock fromUint(std::uint32_t value) {
        BitBlock block;
        for (std::size_t i = 0; i < N; ++i) {
            block.bits_[N - 1 - i] = ((value >> i) & 1U) != 0U;
        }
        return block;
    }

    // -------------------------------------------------------------------------
    // 访问
    // -------------------------------------------------------------------------

    bool at(std::size_t index) const {
        if (index >= N) {
            throw std::out_of_range("BitBlock::at: 索引 " + std::to_string(index) + " 越界（长度 " +
                                    std::to_string(N) + "）");
        }
        return bits_[index];
    }

    void set(std::size_t index, bool value) {
        if (index >= N) {
            throw std::out_of_range("BitBlock::set: 索引 " + std::to_string(index) + " 越界（长度 " +
                                    std::to_string(N) + "）");
        }
        bits_[index] = value;
    }

    // -------------------------------------------------------------------------
    // 转换
    // -------------------------------------------------------------------------

    /// 还原成 "1010000010" 形式的二进制串（长度恰为 N）。
    std::string toString() const {
        std::string text;
        text.reserve(N);
        for (const bool bit : bits_) {
            text.push_back(bit ? '1' : '0');
        }
        return text;
    }

    /// 把位串当作无符号整数读出来（最左位是最高位）。
    std::uint32_t toUint() const noexcept {
        std::uint32_t value = 0;
        for (const bool bit : bits_) {
            value = (value << 1) | (bit ? 1U : 0U);
        }
        return value;
    }

    // -------------------------------------------------------------------------
    // 运算
    // -------------------------------------------------------------------------

    /// 逐位异或（S-DES 中密钥与本轮输入混合所用的运算）。
    BitBlock operator^(const BitBlock& other) const noexcept {
        BitBlock result;
        for (std::size_t i = 0; i < N; ++i) {
            result.bits_[i] = bits_[i] != other.bits_[i];
        }
        return result;
    }

    BitBlock& operator^=(const BitBlock& other) noexcept {
        for (std::size_t i = 0; i < N; ++i) {
            bits_[i] = bits_[i] != other.bits_[i];
        }
        return *this;
    }

    /// 逐位取反。
    BitBlock operator~() const noexcept {
        BitBlock result;
        for (std::size_t i = 0; i < N; ++i) {
            result.bits_[i] = !bits_[i];
        }
        return result;
    }

    bool operator==(const BitBlock& other) const noexcept { return bits_ == other.bits_; }
    bool operator!=(const BitBlock& other) const noexcept { return !(*this == other); }
    bool operator<(const BitBlock& other) const noexcept { return bits_ < other.bits_; }

    /// 循环左移 count 位。
    BitBlock rotateLeft(std::size_t count) const noexcept {
        if (N == 0) {
            return *this;
        }
        count %= N;
        BitBlock result;
        for (std::size_t i = 0; i < N; ++i) {
            result.bits_[i] = bits_[(i + count) % N];
        }
        return result;
    }

    /// 拆成左右两半（要求 N 为偶数）。
    std::pair<BitBlock<N / 2>, BitBlock<N / 2>> split() const {
        static_assert(N % 2 == 0, "split() 要求位串长度为偶数");
        BitBlock<N / 2> left;
        BitBlock<N / 2> right;
        for (std::size_t i = 0; i < N / 2; ++i) {
            left.bits_[i] = bits_[i];
            right.bits_[i] = bits_[N / 2 + i];
        }
        return {left, right};
    }

    /// 把左右两半拼回一个位串（split 的逆运算）。
    static BitBlock concat(const BitBlock<N / 2>& left, const BitBlock<N / 2>& right) {
        static_assert(N % 2 == 0, "concat() 要求位串长度为偶数");
        BitBlock result;
        for (std::size_t i = 0; i < N / 2; ++i) {
            result.bits_[i] = left.bits_[i];
            result.bits_[N / 2 + i] = right.bits_[i];
        }
        return result;
    }

private:
    /// 让 BitBlock 的所有特化互为友元，这样 split / concat 可以直接搬动半分组的内部数组，
    /// 省掉一轮 at()/set() 的边界检查。
    template <std::size_t OtherSize>
    friend class BitBlock;

    /// 位串数据。索引 0 = 最左位。
    std::array<bool, N> bits_{};
};

// -----------------------------------------------------------------------------
//  常用长度别名
// -----------------------------------------------------------------------------
using Block2 = BitBlock<2>;
using Block4 = BitBlock<4>;
using Block5 = BitBlock<5>;
using Block8 = BitBlock<8>;
using Block10 = BitBlock<10>;

// -----------------------------------------------------------------------------
//  置换（P-Box）
// -----------------------------------------------------------------------------

/// 置换表的可读类型别名。OutN 是输出位数，表里每一项是 1-based 的源位序号。
template <std::size_t OutN>
using PermutationTable = std::array<int, OutN>;

/// 按置换表重排位串：output[i] = input[table[i] - 1]。
/// 表中写的是 1-based 的「源位序号」，与作业给出的 P10 / IP / EP 等定义一致。
///
/// 输入输出长度可以不同，例如扩展置换 EP 把 4 bit 拉成 8 bit，
/// 压缩置换 P8 把 10 bit 压成 8 bit。
template <std::size_t InN, std::size_t OutN>
BitBlock<OutN> permute(const BitBlock<InN>& input, const PermutationTable<OutN>& table) {
    BitBlock<OutN> output;
    for (std::size_t i = 0; i < OutN; ++i) {
        const int source = table[i];
        if (source < 1 || static_cast<std::size_t>(source) > InN) {
            throw std::out_of_range("permute: 置换表第 " + std::to_string(i + 1) + " 项取值为 " +
                                    std::to_string(source) + "，超出 1.." + std::to_string(InN));
        }
        output.set(i, input.at(static_cast<std::size_t>(source) - 1));
    }
    return output;
}

// -----------------------------------------------------------------------------
//  8-bit 分组 <-> 字节（第 3 关按 ASCII 字节分组时使用）
// -----------------------------------------------------------------------------

/// 字节 -> 8 bit 位串，字节的最高位对应 at(0)。
inline Block8 blockFromByte(unsigned char value) noexcept {
    return Block8::fromUint(static_cast<std::uint32_t>(value));
}

/// 8 bit 位串 -> 字节。
inline unsigned char byteFromBlock(const Block8& block) noexcept {
    return static_cast<unsigned char>(block.toUint() & 0xFFU);
}

}  // namespace sdes
