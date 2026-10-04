// =============================================================================
//  test_sdes.cpp
//  S-DES 实现的自动化验收测试
//
//  覆盖内容：
//      1. 位串基础类型与置换的互逆性
//      2. 密钥扩展与教材数值的逐项对照
//      3. 教材经典测试向量（证明 P-Box / 轮结构 / 整体流程实现正确）
//      4. 作业 S 盒下的加解密往返一致性（全密钥空间穷举）
//      5. 第 3 关：ASCII 字符串加解密
//      6. 第 4 关：多线程暴力破解，并与单线程结果交叉验证
//      7. 第 5 关：密钥碰撞与等价密钥类统计
//
//  编译：见 scripts/build-cli.ps1，或直接
//      g++ -std=c++17 -Wall -Wextra -O2 -Iinclude src/*.cpp tests/test_sdes.cpp -o build/test_sdes.exe -pthread
// =============================================================================

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#if defined(_WIN32)
#  include <windows.h>
#endif

#include "sdes/analysis.hpp"
#include "sdes/brute_force.hpp"
#include "sdes/cipher.hpp"

namespace {

// -----------------------------------------------------------------------------
//  极简测试框架
// -----------------------------------------------------------------------------

class TestReporter {
public:
    void section(const std::string& title) {
        std::cout << "\n=== " << title << " ===\n";
    }

    void check(bool condition, const std::string& name, const std::string& detail = {}) {
        if (condition) {
            ++passed_;
            std::cout << "  [通过] " << name;
        } else {
            ++failed_;
            std::cout << "  [失败] " << name;
        }
        if (!detail.empty()) {
            std::cout << "  (" << detail << ")";
        }
        std::cout << "\n";
    }

    void note(const std::string& text) const { std::cout << "  [记录] " << text << "\n"; }

    int passed() const { return passed_; }
    int failed() const { return failed_; }

private:
    int passed_ = 0;
    int failed_ = 0;
};

/// 用 [1, 4, 5] 这种形式打印 5 bit 半段，便于和教材对照。
std::string describeHalves(const sdes::Block10& block) {
    const auto [left, right] = block.split();
    return "[" + left.toString() + ", " + right.toString() + "]";
}

// -----------------------------------------------------------------------------
//  1. 位串基础
// -----------------------------------------------------------------------------

void testBitBlock(TestReporter& reporter) {
    reporter.section("1. 位串基础类型 BitBlock");

    using sdes::Block10;
    using sdes::Block8;

    const Block8 parsed = Block8::fromString("10010111");
    reporter.check(parsed.toString() == "10010111", "fromString / toString 往返一致",
                   "得到 " + parsed.toString());
    reporter.check(parsed.at(0) && !parsed.at(1) && parsed.at(3) && parsed.at(7),
                   "索引 0 指向最左位（高位）",
                   "at(0)=" + std::string(parsed.at(0) ? "1" : "0") + ", at(7)=" +
                       std::string(parsed.at(7) ? "1" : "0"));

    // 短输入左侧补零，方便手工输入
    reporter.check(Block8::fromString("101").toString() == "00000101", "短输入在左侧补零",
                   Block8::fromString("101").toString());
    // 非法输入应被拒绝
    reporter.check(!Block8::tryFromString("10020011").has_value(), "非法字符被拒绝");
    reporter.check(!Block8::tryFromString("100000000000").has_value(), "超长输入被拒绝");

    const Block8 value = Block8::fromUint(0x5A);
    reporter.check(value.toString() == "01011010", "fromUint 高位对齐", value.toString());
    reporter.check(value.toUint() == 0x5A, "toUint 与 fromUint 互逆");

    // 异或自反
    reporter.check((value ^ value).toString() == "00000000", "自异或得全零");

    // 循环左移
    reporter.check(Block10::fromString("0110010011").rotateLeft(1).toString() == "1100100110",
                   "10 bit 循环左移 1 位");
    reporter.check(Block10::fromString("10000").rotateLeft(0).toString() == "0000010000",
                   "5 bit 输入按 10 bit 左侧补零后取值");

    // 拆分与拼回
    const Block10 original = Block10::fromString("1000001100");
    const auto [leftHalf, rightHalf] = original.split();
    reporter.check(leftHalf.toString() == "10000" && rightHalf.toString() == "01100",
                   "split 拆成左右各 5 bit", describeHalves(original));
    reporter.check(Block10::concat(leftHalf, rightHalf).toString() == original.toString(),
                   "concat 是 split 的逆运算");
}

// -----------------------------------------------------------------------------
//  2. 置换表与密钥扩展
// -----------------------------------------------------------------------------

void testPermutationAndKeySchedule(TestReporter& reporter) {
    reporter.section("2. 置换表与密钥扩展");

    using sdes::Block10;
    using sdes::Block8;

    // IP 与 IP^-1 必须互逆（对全部 256 个分组逐一验证）
    bool ipInverseHolds = true;
    for (std::uint32_t raw = 0; raw < 256 && ipInverseHolds; ++raw) {
        const Block8 block = Block8::fromUint(raw);
        const Block8 roundTrip = sdes::permute(sdes::permute(block, sdes::tables::kIP),
                                               sdes::tables::kIPInverse);
        ipInverseHolds = (roundTrip == block);
    }
    reporter.check(ipInverseHolds, "IP 与 IP^-1 对全部 256 个分组互逆");

    // 教材给出的密钥扩展结果（与 S 盒无关，改动 S 盒不影响这一项）
    const Block10 masterKey = Block10::fromString("1010000010");

    // 读法 A：教材递进式。k1=10100100、k2=01000011 是公认的标准 S-DES 值。
    const sdes::KeyScheduleTrace progressive =
        sdes::traceKeySchedule(masterKey, sdes::KeyScheduleMode::TextbookProgressive);

    reporter.check(progressive.afterP10.toString() == "1000001100", "P10(K) = 1000001100",
                   progressive.afterP10.toString());
    reporter.check(describeHalves(progressive.afterP10) == "[10000, 01100]",
                   "P10 结果左右两半各 5 bit", describeHalves(progressive.afterP10));
    reporter.check(progressive.afterShift1.toString() == "0000111000",
                   "Shift^1(P10(K)) = 0000111000", progressive.afterShift1.toString());
    reporter.check(progressive.afterShift2.toString() == "0010000011",
                   "Shift^2(P10(K)) = 0010000011（递进式，累计移 3 位）",
                   progressive.afterShift2.toString());
    reporter.check(progressive.k1.toString() == "10100100", "k1 = 10100100（教材标准值）",
                   progressive.k1.toString());
    reporter.check(progressive.k2.toString() == "01000011", "k2 = 01000011（教材标准值）",
                   progressive.k2.toString());

    // 读法 B：严格照抄公式字面。k1 与读法 A 相同，只有 k2 不同。
    const sdes::KeyScheduleTrace literal =
        sdes::traceKeySchedule(masterKey, sdes::KeyScheduleMode::LiteralFormula);
    reporter.check(literal.k1 == progressive.k1, "两种读法得到的 k1 完全相同",
                   literal.k1.toString());
    reporter.check(literal.afterShift2.toString() == "0001010001",
                   "Shift^2(P10(K)) = 0001010001（字面式，只移 2 位）",
                   literal.afterShift2.toString());
    reporter.note("公式字面式下 k2 = " + literal.k2.toString() + "，与递进式的 " +
                  progressive.k2.toString() + " 不同 —— 这会让密文整体不同，交叉测试前必须先统一读法");

    // 循环左移的定义与作业给出的 Left_Shift 表必须一致
    const sdes::Block5 leftFive = sdes::Block5::fromString("10100");
    reporter.check(sdes::permute(leftFive, sdes::tables::kLeftShift1) == leftFive.rotateLeft(1),
                   "Left_Shift^1 表与循环左移 1 位等价");
    reporter.check(sdes::permute(leftFive, sdes::tables::kLeftShift2) == leftFive.rotateLeft(2),
                   "Left_Shift^2 表与循环左移 2 位等价");

    // 全部 1024 个密钥都应派出合法的 8 bit 轮密钥
    bool allKeysValid = true;
    for (std::size_t raw = 0; raw < sdes::kKeySpaceSize && allKeysValid; ++raw) {
        const sdes::RoundKeys roundKeys =
            sdes::deriveRoundKeys(Block10::fromUint(static_cast<std::uint32_t>(raw)));
        allKeysValid = roundKeys.k1.toString().size() == 8 && roundKeys.k2.toString().size() == 8;
    }
    reporter.check(allKeysValid, "全部 1024 个密钥都能派出合法的 8 bit 轮密钥");
}

// -----------------------------------------------------------------------------
//  3. 教材经典测试向量
// -----------------------------------------------------------------------------

void testTextbookVector(TestReporter& reporter) {
    reporter.section("3. 教材经典测试向量（验证实现正确性）");

    using sdes::Block10;
    using sdes::Block8;
    using sdes::Cipher;

    // Schneier《Applied Cryptography》中 S-DES 的标准例子：
    //     K = 1010000010, P = 10010111 -> C = 00111000
    // 用教材原始 S 盒（S1 = 0,2,0,1... 见 tables.hpp）计算，能复现该向量即证明
    // P-Box、轮结构、密钥扩展、Feistel 组合顺序全部实现正确。
    const Block10 key = Block10::fromString("1010000010");
    const Block8 plaintext = Block8::fromString("10010111");

    const Cipher textbookCipher(key, sdes::SBoxSet::textbook());
    const Block8 textbookCiphertext = textbookCipher.encrypt(plaintext);
    reporter.check(textbookCiphertext.toString() == "00111000",
                   "教材 S 盒: K=1010000010, P=10010111 -> C=00111000",
                   "实际得到 " + textbookCiphertext.toString());
    reporter.check(textbookCipher.decrypt(textbookCiphertext) == plaintext,
                   "教材 S 盒: 解密可还原明文");

    // 换成作业指定的 S 盒（SBox_2 第 2、3 行与教材不同）
    const Cipher homeworkCipher(key, sdes::SBoxSet::homework());
    const Block8 homeworkCiphertext = homeworkCipher.encrypt(plaintext);
    reporter.note("作业 S 盒: K=1010000010, P=10010111 -> C=" + homeworkCiphertext.toString() +
                  (homeworkCiphertext.toString() == "00111000"
                       ? "，与教材向量恰好一致（改动未影响该向量）"
                       : "，与教材向量不同（这是 SBox_2 改动带来的必然结果）"));
    reporter.check(homeworkCipher.decrypt(homeworkCiphertext) == plaintext,
                   "作业 S 盒: 解密可还原明文", homeworkCiphertext.toString());

    // 统计两套 S 盒的差异规模，量化这次改动的影响面
    std::size_t differingCases = 0;
    for (std::size_t rawKey = 0; rawKey < sdes::kKeySpaceSize; ++rawKey) {
        const Block10 currentKey = Block10::fromUint(static_cast<std::uint32_t>(rawKey));
        const Cipher withTextbook(currentKey, sdes::SBoxSet::textbook());
        const Cipher withHomework(currentKey, sdes::SBoxSet::homework());
        for (std::uint32_t rawPlain = 0; rawPlain < 256; ++rawPlain) {
            const Block8 block = Block8::fromUint(rawPlain);
            if (withTextbook.encrypt(block) != withHomework.encrypt(block)) {
                ++differingCases;
            }
        }
    }
    reporter.note("两套 S 盒在 1024 x 256 = 262144 个组合中有 " + std::to_string(differingCases) +
                  " 个结果不同");
}

// -----------------------------------------------------------------------------
//  4. 作业标准下的加解密往返
// -----------------------------------------------------------------------------

void testRoundTrip(TestReporter& reporter) {
    reporter.section("4. 加解密往返一致性（穷举全部 1024 个密钥）");

    using sdes::Block10;
    using sdes::Block8;
    using sdes::Cipher;

    std::size_t mismatches = 0;
    for (std::size_t rawKey = 0; rawKey < sdes::kKeySpaceSize; ++rawKey) {
        const Cipher cipher(Block10::fromUint(static_cast<std::uint32_t>(rawKey)));
        for (std::uint32_t rawPlain = 0; rawPlain < 256; ++rawPlain) {
            const Block8 plaintext = Block8::fromUint(rawPlain);
            const Block8 recovered = cipher.decrypt(cipher.encrypt(plaintext));
            if (recovered != plaintext) {
                ++mismatches;
            }
        }
    }
    reporter.check(mismatches == 0, "1024 个密钥 x 256 个明文全部往返还原成功",
                   "不匹配 " + std::to_string(mismatches) + " 例");

    // 加密必须是双射：同一密钥下不同明文不能产生相同密文
    const Cipher sampleCipher(Block10::fromString("1100011010"));
    std::vector<std::string> ciphertexts;
    for (std::uint32_t rawPlain = 0; rawPlain < 256; ++rawPlain) {
        ciphertexts.push_back(sampleCipher.encrypt(Block8::fromUint(rawPlain)).toString());
    }
    std::sort(ciphertexts.begin(), ciphertexts.end());
    reporter.check(std::adjacent_find(ciphertexts.begin(), ciphertexts.end()) == ciphertexts.end(),
                   "固定密钥下加密是双射（256 个密文互不相同）");
}

// -----------------------------------------------------------------------------
//  5. 第 3 关：字符串加解密
// -----------------------------------------------------------------------------

void testTextMode(TestReporter& reporter) {
    reporter.section("5. 第 3 关：ASCII 字符串加解密");

    const sdes::Block10 key = sdes::Block10::fromString("1010000010");
    const sdes::Cipher cipher(key);

    const std::string plaintext = "Information Security";
    const std::string ciphertext = cipher.encryptText(plaintext);
    const std::string recovered = cipher.decryptText(ciphertext);

    reporter.check(recovered == plaintext, "字符串加解密往返一致",
                   "明文长度 " + std::to_string(plaintext.size()) + " 字节");
    reporter.check(ciphertext.size() == plaintext.size(), "密文长度等于明文长度（逐字节分组）");

    std::ostringstream hexStream;
    for (const unsigned char character : ciphertext) {
        hexStream << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                  << static_cast<int>(character);
    }
    reporter.note("明文 \"" + plaintext + "\" 的密文十六进制 = " + hexStream.str());

    // 空串与单字符边界
    reporter.check(cipher.encryptText("").empty(), "空串加密为空串");
    reporter.check(cipher.decryptText(cipher.encryptText("A")) == "A", "单字符往返一致");

    // 含汉字等高位字节的输入（按原始字节逐字节处理，不依赖具体编码）
    const std::string unicodeText = "信息安全导论";
    reporter.check(cipher.decryptText(cipher.encryptText(unicodeText)) == unicodeText,
                   "多字节编码文本（UTF-8 汉字）往返一致");
}

// -----------------------------------------------------------------------------
//  6. 第 4 关：暴力破解
// -----------------------------------------------------------------------------

void testBruteForce(TestReporter& reporter) {
    reporter.section("6. 第 4 关：暴力破解");

    using sdes::Block10;
    using sdes::Block8;
    using sdes::Cipher;
    using sdes::KnownPair;

    // 用一个固定的「秘密密钥」生成待破解的明密文对
    const Block10 secretKey = Block10::fromString("1100101010");
    const Cipher secretCipher(secretKey);

    const Block8 plaintextA = Block8::fromString("10010111");
    const Block8 plaintextB = Block8::fromString("00001111");
    const std::vector<KnownPair> pairs{
        KnownPair{plaintextA, secretCipher.encrypt(plaintextA)},
        KnownPair{plaintextB, secretCipher.encrypt(plaintextB)},
    };

    reporter.note("秘密密钥 " + secretKey.toString() + "，明文 " + plaintextA.toString() + " -> 密文 " +
                  pairs[0].ciphertext.toString());

    const sdes::BruteForceResult multiThreaded = sdes::bruteForceKey(pairs);
    reporter.check(multiThreaded.stats.keysTested == sdes::kKeySpaceSize,
                   "穷举覆盖整个密钥空间",
                   std::to_string(multiThreaded.stats.keysTested) + " / " +
                       std::to_string(multiThreaded.stats.keySpaceSize));
    reporter.check(std::find(multiThreaded.candidateKeys.begin(), multiThreaded.candidateKeys.end(),
                             secretKey) != multiThreaded.candidateKeys.end(),
                   "破解结果包含真实密钥");
    reporter.note("使用 " + std::to_string(multiThreaded.stats.workerThreads) + " 个线程，耗时 " +
                  std::to_string(multiThreaded.stats.elapsedMicroseconds()) + " 微秒（" +
                  std::to_string(multiThreaded.stats.elapsedMilliseconds()) + " 毫秒）");
    reporter.note("命中候选密钥 " + std::to_string(multiThreaded.candidateKeys.size()) + " 个");

    const sdes::BruteForceResult singleThreaded = sdes::bruteForceKeySingleThreaded(pairs);
    reporter.check(singleThreaded.candidateKeys == multiThreaded.candidateKeys,
                   "多线程结果与单线程结果完全一致",
                   "单线程耗时 " + std::to_string(singleThreaded.stats.elapsedMilliseconds()) + " 毫秒");

    // 指定线程数也应得到相同结果
    bool allThreadCountsAgree = true;
    for (unsigned threadCount = 1; threadCount <= 8; ++threadCount) {
        sdes::BruteForceOptions options;
        options.workerThreads = threadCount;
        const sdes::BruteForceResult result = sdes::bruteForceKey(pairs, options);
        if (result.candidateKeys != multiThreaded.candidateKeys ||
            result.stats.keysTested != sdes::kKeySpaceSize) {
            allThreadCountsAgree = false;
            break;
        }
    }
    reporter.check(allThreadCountsAgree, "1~8 线程下结果均一致");

    // 只有一对明密文时，候选密钥通常不止一个 —— 这正是第 5 关要分析的现象
    const std::vector<KnownPair> singlePair{std::vector<KnownPair>{pairs[0]}};
    sdes::BruteForceOptions singlePairOptions;
    singlePairOptions.workerThreads = 4;
    const sdes::BruteForceResult onePairResult = sdes::bruteForceKey(singlePair, singlePairOptions);
    reporter.note("只用一对明密文时命中候选密钥 " + std::to_string(onePairResult.candidateKeys.size()) +
                  " 个");
    reporter.check(onePairResult.candidateKeys.size() >= multiThreaded.candidateKeys.size(),
                   "已知明文对越少，候选密钥不会更少");
}

// -----------------------------------------------------------------------------
//  7. 第 5 关：密钥空间结构
// -----------------------------------------------------------------------------

void testKeySpaceStructure(TestReporter& reporter) {
    reporter.section("7. 第 5 关：密钥空间结构分析");

    using sdes::Block8;

    // 问题 B：固定明文，不同密钥是否会给出相同密文
    const Block8 plaintext = Block8::fromString("10010111");
    const sdes::PlaintextAnalysis analysis = sdes::analysePlaintext(plaintext);

    reporter.note("明文 " + analysis.plaintext.toString() + " 在 1024 个密钥下的密文分布：");
    reporter.note("  不同密文个数         = " + std::to_string(analysis.distinctCiphertexts) +
                  " / 256");
    reporter.note("  只对应唯一密钥的密文 = " + std::to_string(analysis.singleKeyCiphertexts));
    reporter.note("  存在多个密钥的密文   = " + std::to_string(analysis.collidingCiphertexts));
    reporter.note("  最严重碰撞的密文     = " + analysis.mostCommonCiphertext.toString() +
                  "（对应 " + std::to_string(analysis.maxKeysPerCiphertext) + " 个密钥）");
    reporter.note("  平均每个密文对应密钥 = " + std::to_string(analysis.averageKeysPerCiphertext));

    reporter.check(analysis.keyCount == sdes::kKeySpaceSize, "穷举了全部 1024 个密钥");
    reporter.check(analysis.distinctCiphertexts < sdes::kKeySpaceSize,
                   "密文个数少于密钥个数：必然存在密钥碰撞（鸽巢原理）");
    reporter.check(analysis.collidingCiphertexts > 0, "确实存在「多密钥 -> 同一密文」的情形");
    reporter.check(analysis.singleKeyCiphertexts + analysis.collidingCiphertexts ==
                       analysis.distinctCiphertexts,
                   "按密钥个数分类后的密文数之和等于不同密文总数");
    reporter.check(analysis.keysInCollisions + analysis.singleKeyCiphertexts == analysis.keyCount,
                   "全部 1024 个密钥都被计入统计");

    // -------------------------------------------------------------------------
    //  问题 A：给定一对明密文，会不会有不止一个密钥？
    //  直接用上面统计出的「碰撞最严重」的密文构造明密文对，再做暴力破解。
    // -------------------------------------------------------------------------
    const std::vector<sdes::KnownPair> collidingPair{
        sdes::KnownPair{plaintext, analysis.mostCommonCiphertext}};
    const sdes::BruteForceResult cracked = sdes::bruteForceKey(collidingPair);
    reporter.note("对明密文对 (" + plaintext.toString() + ", " +
                  analysis.mostCommonCiphertext.toString() + ") 暴力破解，命中 " +
                  std::to_string(cracked.candidateKeys.size()) + " 个候选密钥");
    reporter.check(cracked.candidateKeys.size() == analysis.maxKeysPerCiphertext,
                   "暴力破解命中的密钥个数与统计分析的碰撞计数一致",
                   std::to_string(cracked.candidateKeys.size()) + " vs " +
                       std::to_string(analysis.maxKeysPerCiphertext));
    reporter.check(cracked.candidateKeys.size() > 1,
                   "一对明密文确实可能对应不止一个密钥（问题 A 的答案是「是」）");

    // 再补一对明密文，候选范围应当继续缩小
    if (!cracked.candidateKeys.empty()) {
        const sdes::Cipher referenceCipher(cracked.candidateKeys.front());
        const Block8 secondPlaintext = Block8::fromString("00001111");
        const std::vector<sdes::KnownPair> twoPairs{
            sdes::KnownPair{plaintext, analysis.mostCommonCiphertext},
            sdes::KnownPair{secondPlaintext, referenceCipher.encrypt(secondPlaintext)},
        };
        const sdes::BruteForceResult narrowed = sdes::bruteForceKey(twoPairs);
        reporter.note("补充第二对明密文后，候选密钥降到 " +
                      std::to_string(narrowed.candidateKeys.size()) + " 个");
        reporter.check(narrowed.candidateKeys.size() < cracked.candidateKeys.size(),
                       "增加已知明密文对能继续缩小候选密钥范围");
    }

    // -------------------------------------------------------------------------
    //  全局结构：是否存在「对任意明文都等价」的密钥对
    // -------------------------------------------------------------------------
    std::vector<sdes::EquivalentKeyClass> classes;
    const sdes::KeySpaceAnalysis spaceAnalysis = sdes::analyseKeySpace(classes);

    reporter.note("密钥空间整体结构（教材递进式读法）：");
    reporter.note("  密钥总数             = " + std::to_string(spaceAnalysis.keySpaceSize));
    reporter.note("  不同 (k1,k2) 组合数  = " + std::to_string(spaceAnalysis.distinctRoundKeyPairs));
    reporter.note("  不同加密映射个数     = " + std::to_string(spaceAnalysis.distinctPermutations));
    reporter.note("  单元素等价类个数     = " + std::to_string(spaceAnalysis.trivialClassCount));
    reporter.note("  多元素等价类个数     = " + std::to_string(spaceAnalysis.nontrivialClassCount));
    reporter.note("  最大等价类大小       = " + std::to_string(spaceAnalysis.largestClassSize));
    reporter.note("  平均等价类大小       = " + std::to_string(spaceAnalysis.averageClassSize));
    reporter.note("  有效密钥位数         = " + std::to_string(spaceAnalysis.effectiveKeyBits) + " bit");

    reporter.check(spaceAnalysis.distinctRoundKeyPairs == sdes::kKeySpaceSize,
                   "密钥扩展是单射：1024 个密钥给出 1024 组不同的 (k1,k2)");
    reporter.check(spaceAnalysis.distinctPermutations == sdes::kKeySpaceSize,
                   "1024 个密钥的加密映射两两不同，不存在全局等价的密钥对");
    reporter.check(spaceAnalysis.nontrivialClassCount == 0, "全部等价类都是单元素类");
    reporter.check(spaceAnalysis.effectiveKeyBits == 10, "有效密钥位数保持 10 bit");

    std::size_t classSum = 0;
    for (const sdes::EquivalentKeyClass& keyClass : classes) {
        classSum += keyClass.keys.size();
    }
    reporter.check(classSum == sdes::kKeySpaceSize, "各等价类大小之和等于密钥总数");

    // 对照实验：若按公式字面读法，密钥扩展会丢掉 1 bit 信息，出现等价密钥类
    std::vector<sdes::EquivalentKeyClass> literalClasses;
    const sdes::KeySpaceAnalysis literalSpace =
        sdes::analyseKeySpace(literalClasses, sdes::KeyScheduleMode::LiteralFormula);
    reporter.note("对照（公式字面式读法）：不同 (k1,k2) 组合 = " +
                  std::to_string(literalSpace.distinctRoundKeyPairs) + "，不同加密映射 = " +
                  std::to_string(literalSpace.distinctPermutations) + "，最大等价类 = " +
                  std::to_string(literalSpace.largestClassSize) + " 个密钥，有效密钥位数 = " +
                  std::to_string(literalSpace.effectiveKeyBits) + " bit");
    reporter.check(literalSpace.distinctPermutations < sdes::kKeySpaceSize,
                   "公式字面式读法下会出现等价密钥类（10 bit 密钥实际只有 9 bit 强度）");
    if (!literalClasses.empty() && literalClasses.front().keys.size() >= 2) {
        // 注意：等价类是在「公式字面式读法」下算出来的，验证时也必须用同一读法。
        const sdes::Cipher firstOfClass(literalClasses.front().keys.front(), sdes::SBoxSet::homework(),
                                        sdes::KeyScheduleMode::LiteralFormula);
        const sdes::Cipher secondOfClass(literalClasses.front().keys[1], sdes::SBoxSet::homework(),
                                         sdes::KeyScheduleMode::LiteralFormula);
        bool identical = true;
        for (std::uint32_t raw = 0; raw < 256 && identical; ++raw) {
            const Block8 block = Block8::fromUint(raw);
            identical = (firstOfClass.encrypt(block) == secondOfClass.encrypt(block));
        }
        reporter.check(identical, "该读法下的等价密钥对，对全部 256 个明文加密结果一致",
                       literalClasses.front().keys.front().toString() + " 与 " +
                           literalClasses.front().keys[1].toString());
    }
}

}  // namespace

int main() {
#if defined(_WIN32)
    // 让控制台按 UTF-8 输出中文
    SetConsoleOutputCP(CP_UTF8);
#endif

    std::cout << "========================================================\n";
    std::cout << "  S-DES 实现自动化验收测试\n";
    std::cout << "  作业：信息安全导论 · 第 5 次课 · S-DES 加解密程序\n";
    std::cout << "========================================================\n";

    TestReporter reporter;
    const std::chrono::steady_clock::time_point startedAt = std::chrono::steady_clock::now();

    testBitBlock(reporter);
    testPermutationAndKeySchedule(reporter);
    testTextbookVector(reporter);
    testRoundTrip(reporter);
    testTextMode(reporter);
    testBruteForce(reporter);
    testKeySpaceStructure(reporter);

    const std::chrono::steady_clock::time_point finishedAt = std::chrono::steady_clock::now();
    const double elapsedSeconds = std::chrono::duration<double>(finishedAt - startedAt).count();

    std::cout << "\n========================================================\n";
    std::cout << "  合计：" << reporter.passed() << " 项通过，" << reporter.failed() << " 项失败，用时 "
              << std::fixed << std::setprecision(3) << elapsedSeconds << " 秒\n";
    std::cout << "========================================================\n";

    return reporter.failed() == 0 ? 0 : 1;
}
