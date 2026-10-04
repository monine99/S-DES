// =============================================================================
//  apps/cli/main.cpp
//  S-DES 命令行前端 —— 覆盖作业的五关，并内置一份可直接拿去做交叉测试的标准向量表
//
//  用法：
//      sdes-cli demo                          一键跑完五关（截图 / 写报告用）
//      sdes-cli vectors                       输出标准交叉测试向量表
//      sdes-cli encrypt --key 1010000010 --input 10010111
//      sdes-cli decrypt --key 1010000010 --input 00111000
//      sdes-cli text    --key 1010000010 --encrypt "Hello"
//      sdes-cli text    --key 1010000010 --decrypt <密文的十六进制>
//      sdes-cli brute   --pair 10010111:00111000 [--pair ...] [--threads 4]
//      sdes-cli analyse --plain 10010111
//      sdes-cli keyspace                      密钥空间整体结构（第 5 关的扩展分析）
//      sdes-cli            （不带参数）       进入交互式菜单
//
//  所有子命令都可加：
//      --mode textbook|literal    密钥扩展读法（默认 textbook，见 key_schedule.hpp）
//      --sbox homework|textbook   S 盒版本（默认 homework，即作业指定版本）
// =============================================================================

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#if defined(_WIN32)
#  include <windows.h>
#endif

#include "sdes/analysis.hpp"
#include "sdes/brute_force.hpp"
#include "sdes/cipher.hpp"

namespace {

// =============================================================================
//  小工具：终端排版与格式化
// =============================================================================

/// 计算字符串在终端里占的显示宽度（UTF-8：CJK 字符按 2 列算）。
std::size_t displayWidth(const std::string& text) {
    std::size_t width = 0;
    for (std::size_t index = 0; index < text.size();) {
        const unsigned char lead = static_cast<unsigned char>(text[index]);
        if (lead < 0x80) {
            ++width;
            index += 1;
        } else if ((lead >> 5) == 0x06) {
            width += 1;  // 2 字节序列（拉丁扩展等）
            index += 2;
        } else if ((lead >> 4) == 0x0E) {
            width += 2;  // 3 字节序列（中日韩等全角字符）
            index += 3;
        } else {
            width += 2;  // 4 字节序列
            index += 4;
        }
    }
    return width;
}

/// 右侧补空格到指定显示宽度。
std::string padRight(const std::string& text, std::size_t width) {
    const std::size_t current = displayWidth(text);
    if (current >= width) {
        return text;
    }
    return text + std::string(width - current, ' ');
}

/// 一行分隔线。
std::string rule(std::size_t width = 76) { return std::string(width, '-'); }

/// 把时间点格式化成 "2026-10-08 21:33:12.345"。
std::string formatTimestamp(std::chrono::system_clock::time_point timePoint) {
    const std::time_t rawTime = std::chrono::system_clock::to_time_t(timePoint);
    const std::tm* localTime = std::localtime(&rawTime);
    if (localTime == nullptr) {
        return "(未知时刻)";
    }

    const auto millisecondPart =
        std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch()).count() %
        1000;

    std::ostringstream stream;
    stream << std::put_time(localTime, "%Y-%m-%d %H:%M:%S") << '.' << std::setw(3)
           << std::setfill('0') << millisecondPart;
    return stream.str();
}

/// 把字节串转成可读的十六进制。
std::string toHex(const std::string& data) {
    std::ostringstream stream;
    for (const unsigned char byte : data) {
        stream << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
               << static_cast<int>(byte);
    }
    return stream.str();
}

/// 把不可打印字节替换成 '.'，避免密文里的控制字符扰乱终端显示。
std::string toPrintable(const std::string& data) {
    std::string result;
    result.reserve(data.size());
    for (const unsigned char byte : data) {
        result.push_back((byte >= 0x20 && byte < 0x7F) ? static_cast<char>(byte) : '.');
    }
    return result;
}

/// 把十六进制串还原成字节串。
std::optional<std::string> fromHex(const std::string& hexText) {
    std::string cleaned;
    for (const char character : hexText) {
        if (std::isxdigit(static_cast<unsigned char>(character)) != 0) {
            cleaned.push_back(character);
        } else if (character == ' ' || character == ':' || character == '-' || character == '\t') {
            continue;  // 允许用空格/冒号/短横线分组
        } else {
            return std::nullopt;
        }
    }
    if (cleaned.size() % 2 != 0) {
        return std::nullopt;
    }

    std::string bytes;
    bytes.reserve(cleaned.size() / 2);
    for (std::size_t index = 0; index < cleaned.size(); index += 2) {
        const int highNibble = std::stoi(cleaned.substr(index, 1), nullptr, 16);
        const int lowNibble = std::stoi(cleaned.substr(index + 1, 1), nullptr, 16);
        bytes.push_back(static_cast<char>((highNibble << 4) | lowNibble));
    }
    return bytes;
}

// =============================================================================
//  小工具：S 盒与读法的可读名称
// =============================================================================

std::string describeSBoxSet(const sdes::SBoxSet& boxes) {
    return boxes.sBox2 == &sdes::tables::kSBox2 ? "作业指定版本（SBox_2 已按 PPT 修改）"
                                                : "Schneier 教材原始版本";
}

/// 从 --mode 的取值解析读法。
std::optional<sdes::KeyScheduleMode> parseKeyScheduleMode(const std::string& text) {
    if (text == "textbook" || text == "progressive" || text == "a") {
        return sdes::KeyScheduleMode::TextbookProgressive;
    }
    if (text == "literal" || text == "formula" || text == "b") {
        return sdes::KeyScheduleMode::LiteralFormula;
    }
    return std::nullopt;
}

// =============================================================================
//  命令行解析
// =============================================================================

/// 极简参数解析器：支持 `--名字 值`、`--开关`，其余算位置参数。
class ArgumentParser {
public:
    explicit ArgumentParser(const std::vector<std::string>& arguments) {
        for (std::size_t index = 0; index < arguments.size(); ++index) {
            const std::string& token = arguments[index];
            if (token.rfind("--", 0) == 0) {
                const std::string name = token.substr(2);
                // 下一个 token 不是选项则视为本选项的值
                if (index + 1 < arguments.size() && arguments[index + 1].rfind("--", 0) != 0) {
                    options_[name].push_back(arguments[index + 1]);
                    ++index;
                } else {
                    options_[name];  // 存一个空列表表示「开关已给出」
                }
            } else {
                positional_.push_back(token);
            }
        }
    }

    bool has(const std::string& name) const { return options_.find(name) != options_.end(); }

    std::string get(const std::string& name, const std::string& fallback = {}) const {
        const auto found = options_.find(name);
        if (found == options_.end() || found->second.empty()) {
            return fallback;
        }
        return found->second.front();
    }

    std::vector<std::string> getAll(const std::string& name) const {
        const auto found = options_.find(name);
        if (found == options_.end()) {
            return {};
        }
        return found->second;
    }

    const std::vector<std::string>& positional() const { return positional_; }

private:
    std::map<std::string, std::vector<std::string>> options_;
    std::vector<std::string> positional_;
};

/// 运行环境（读法 + S 盒），由 --mode / --sbox 决定。
struct RuntimeConfig {
    sdes::KeyScheduleMode mode = sdes::kDefaultKeyScheduleMode;
    sdes::SBoxSet sBoxes = sdes::SBoxSet::homework();

    sdes::Cipher makeCipher(const sdes::Block10& key) const { return sdes::Cipher(key, sBoxes, mode); }
};

bool applyRuntimeOptions(const ArgumentParser& parser, RuntimeConfig& config, std::string& error) {
    if (parser.has("mode")) {
        const std::optional<sdes::KeyScheduleMode> mode = parseKeyScheduleMode(parser.get("mode"));
        if (!mode.has_value()) {
            error = "--mode 只能是 textbook 或 literal";
            return false;
        }
        config.mode = *mode;
    }
    if (parser.has("sbox")) {
        const std::string name = parser.get("sbox");
        if (name == "homework") {
            config.sBoxes = sdes::SBoxSet::homework();
        } else if (name == "textbook") {
            config.sBoxes = sdes::SBoxSet::textbook();
        } else {
            error = "--sbox 只能是 homework 或 textbook";
            return false;
        }
    }
    return true;
}

/// 从字符串读一个 10 bit 密钥，失败返回 nullopt 并填充 error。
std::optional<sdes::Block10> readKey(const std::string& text, std::string& error) {
    const std::optional<sdes::Block10> key = sdes::Block10::tryFromString(text);
    if (!key.has_value()) {
        error = "\"" + text + "\" 不是合法的 10 bit 密钥（只允许 0/1，最多 10 位）";
    }
    return key;
}

/// 从字符串读一个 8 bit 分组。
std::optional<sdes::Block8> readBlock(const std::string& text, std::string& error) {
    const std::optional<sdes::Block8> block = sdes::Block8::tryFromString(text);
    if (!block.has_value()) {
        error = "\"" + text + "\" 不是合法的 8 bit 分组（只允许 0/1，最多 8 位）";
    }
    return block;
}

// =============================================================================
//  打印：加解密的完整中间过程
// =============================================================================

void printKeySchedule(const sdes::Cipher& cipher) {
    const sdes::KeyScheduleTrace trace = sdes::traceKeySchedule(cipher.masterKey(), cipher.keyScheduleMode());
    std::cout << "  密钥 K          = " << trace.masterKey.toString() << "\n";
    std::cout << "  P10(K)          = " << trace.afterP10.toString() << "   (左半 "
              << trace.afterP10.split().first.toString() << " | 右半 "
              << trace.afterP10.split().second.toString() << ")\n";
    std::cout << "  Shift^1(P10(K)) = " << trace.afterShift1.toString() << "   -> k1 = " << trace.k1.toString()
              << "\n";
    std::cout << "  Shift^2(P10(K)) = " << trace.afterShift2.toString() << "   -> k2 = " << trace.k2.toString()
              << "\n";
}

void printCipherTrace(const sdes::CipherTrace& trace) {
    std::cout << "  IP(输入)        = " << trace.afterIP.toString() << "   (左半 "
              << trace.leftBeforeRound1.toString() << " | 右半 " << trace.rightBeforeRound1.toString()
              << ")\n";
    std::cout << "  第 1 轮 密钥    = " << trace.firstRoundKey.toString() << "   f_k1 = "
              << trace.afterFeistel1.toString() << "   轮输出 = " << trace.afterRound1.toString() << "\n";
    std::cout << "  SW 之后         = " << trace.afterSwap.toString() << "   (左半 "
              << trace.leftBeforeRound2.toString() << " | 右半 " << trace.rightBeforeRound2.toString()
              << ")\n";
    std::cout << "  第 2 轮 密钥    = " << trace.secondRoundKey.toString() << "   f_k2 = "
              << trace.afterFeistel2.toString() << "   轮输出 = " << trace.afterRound2.toString() << "\n";
    std::cout << "  IP^-1 之后      = " << trace.output.toString() << "\n";
}

// =============================================================================
//  第 1 关：基本测试
// =============================================================================

void printStage1(const RuntimeConfig& config) {
    std::cout << "\n【第 1 关】基本测试 —— 8 bit 明文 + 10 bit 密钥\n";
    std::cout << rule() << "\n";

    const std::string keyText = "1010000010";
    const std::string plainText = "10010111";
    const sdes::Block10 key = sdes::Block10::fromString(keyText);
    const sdes::Block8 plaintext = sdes::Block8::fromString(plainText);
    const sdes::Cipher cipher = config.makeCipher(key);

    std::cout << "  密钥扩展：\n";
    printKeySchedule(cipher);

    std::cout << "\n  加密过程：\n";
    const sdes::CipherTrace encryptTrace = cipher.traceEncrypt(plaintext);
    printCipherTrace(encryptTrace);

    const sdes::Block8 ciphertext = encryptTrace.output;
    std::cout << "\n  明文 P          = " << plaintext.toString() << "\n";
    std::cout << "  密文 C          = " << ciphertext.toString() << "\n";

    std::cout << "\n  解密过程：\n";
    const sdes::CipherTrace decryptTrace = cipher.traceDecrypt(ciphertext);
    printCipherTrace(decryptTrace);

    const bool restored = (decryptTrace.output == plaintext);
    std::cout << "\n  解密结果        = " << decryptTrace.output.toString() << "   "
              << (restored ? "[与原明文一致]" : "[不一致！]") << "\n";
}

// =============================================================================
//  第 2 关：交叉测试向量表
// =============================================================================

struct TestVector {
    const char* key;
    const char* plaintext;
};

constexpr TestVector kCrossTestVectors[] = {
    {"1010000010", "10010111"},  // Schneier 教材经典向量
    {"0000000000", "00000000"},  // 边界：全零
    {"1111111111", "11111111"},  // 边界：全一
    {"1100101010", "10010111"},  // 与第 4 关的「秘密密钥」一致
    {"1010101010", "01010101"},  // 交替位
    {"0111111110", "11110000"},
    {"1000000001", "00001111"},
    {"0011001100", "10101010"},
};

void printStage2(const RuntimeConfig& config) {
    std::cout << "\n【第 2 关】交叉测试 —— 标准测试向量表\n";
    std::cout << rule() << "\n";
    std::cout << "  下面每一行的密文都由本程序按标准流程算出。B 组同学用自己写的程序\n";
    std::cout << "  加密同一组 (K, P)，如果得到的 C 与表中完全一致，即通过交叉测试。\n\n";

    const std::size_t columnWidthNumber = 6;
    const std::size_t columnWidthKey = 14;
    const std::size_t columnWidthBlock = 12;

    std::cout << "  " << padRight("序号", columnWidthNumber) << padRight("密钥 K (10 bit)", columnWidthKey + 2)
              << padRight("明文 P", columnWidthBlock) << padRight("密文 C", columnWidthBlock)
              << "解密还原\n";
    std::cout << "  " << padRight("----", columnWidthNumber) << padRight("--------------", columnWidthKey + 2)
              << padRight("----------", columnWidthBlock) << padRight("----------", columnWidthBlock)
              << "--------\n";

    std::size_t index = 1;
    for (const TestVector& vector : kCrossTestVectors) {
        const sdes::Cipher cipher = config.makeCipher(sdes::Block10::fromString(vector.key));
        const sdes::Block8 plaintext = sdes::Block8::fromString(vector.plaintext);
        const sdes::Block8 ciphertext = cipher.encrypt(plaintext);
        const bool restored = (cipher.decrypt(ciphertext) == plaintext);

        std::cout << "  " << padRight(std::to_string(index), columnWidthNumber)
                  << padRight(cipher.masterKey().toString(), columnWidthKey + 2)
                  << padRight(plaintext.toString(), columnWidthBlock)
                  << padRight(ciphertext.toString(), columnWidthBlock)
                  << (restored ? "OK" : "失败") << "\n";
        ++index;
    }

    // 顺带给出该读法下的 k1 / k2，方便组员核对密钥扩展这一步
    std::cout << "\n  对应的轮密钥（便于逐步核对密钥扩展）：\n";
    std::cout << "  " << padRight("序号", columnWidthNumber) << padRight("密钥 K", columnWidthKey + 2)
              << padRight("k1", columnWidthBlock) << "k2\n";
    index = 1;
    for (const TestVector& vector : kCrossTestVectors) {
        const sdes::RoundKeys roundKeys =
            sdes::deriveRoundKeys(sdes::Block10::fromString(vector.key), config.mode);
        std::cout << "  " << padRight(std::to_string(index), columnWidthNumber)
                  << padRight(vector.key, columnWidthKey + 2) << padRight(roundKeys.k1.toString(), columnWidthBlock)
                  << roundKeys.k2.toString() << "\n";
        ++index;
    }
}

// =============================================================================
//  第 3 关：字符串加解密
// =============================================================================

void printStage3(const RuntimeConfig& config) {
    std::cout << "\n【第 3 关】扩展功能 —— ASCII 字符串加解密（按 1 Byte 分组）\n";
    std::cout << rule() << "\n";

    const sdes::Block10 key = sdes::Block10::fromString("1010000010");
    const sdes::Cipher cipher = config.makeCipher(key);

    const std::string plaintext = "Information Security";
    const std::string ciphertext = cipher.encryptText(plaintext);
    const std::string recovered = cipher.decryptText(ciphertext);

    std::cout << "  密钥 K          = " << key.toString() << "\n";
    std::cout << "  明文            = \"" << plaintext << "\"（" << plaintext.size() << " 字节）\n";
    std::cout << "  密文（十六进制）= " << toHex(ciphertext) << "\n";
    std::cout << "  密文（可显示化）= " << toPrintable(ciphertext)
              << "   <- 不可打印字节用 . 代替；分组密码的直接输出本来就多为乱码\n";
    std::cout << "  解密还原        = \"" << recovered << "\"   "
              << (recovered == plaintext ? "[一致]" : "[不一致！]") << "\n";

    // 逐字节展示前 8 个字节的映射关系，体现「1 Byte 一组」
    std::cout << "\n  逐字节映射（前 8 个字节）：\n";
    std::cout << "  " << padRight("字节", 6) << padRight("字符", 8) << padRight("明文分组", 14)
              << padRight("密文分组", 14) << "密文字节\n";
    const std::size_t shownBytes = std::min<std::size_t>(8, plaintext.size());
    for (std::size_t index = 0; index < shownBytes; ++index) {
        const sdes::Block8 plainBlock = sdes::blockFromByte(static_cast<unsigned char>(plaintext[index]));
        const sdes::Block8 cipherBlock = cipher.encrypt(plainBlock);
        std::ostringstream hexByte;
        hexByte << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                << static_cast<int>(sdes::byteFromBlock(cipherBlock));
        std::cout << "  " << padRight(std::to_string(index + 1), 6)
                  << padRight(std::string(1, plaintext[index]), 8) << padRight(plainBlock.toString(), 14)
                  << padRight(cipherBlock.toString(), 14) << "0x" << hexByte.str() << "\n";
    }
}

// =============================================================================
//  第 4 关：暴力破解
// =============================================================================

void printStage4(const RuntimeConfig& config) {
    std::cout << "\n【第 4 关】暴力破解 —— 由明密文对反推密钥\n";
    std::cout << rule() << "\n";

    // 构造一个「未知」的秘密密钥，再假装只知道一对明密文
    const sdes::Block10 secretKey = sdes::Block10::fromString("1100101010");
    const sdes::Cipher secretCipher = config.makeCipher(secretKey);
    const sdes::Block8 plaintext = sdes::Block8::fromString("10010111");
    const sdes::Block8 ciphertext = secretCipher.encrypt(plaintext);

    std::cout << "  已知明文 P      = " << plaintext.toString() << "\n";
    std::cout << "  已知密文 C      = " << ciphertext.toString() << "\n";
    std::cout << "  （真实密钥 " << secretKey.toString() << " 在破解前对程序不可见）\n\n";

    const std::vector<sdes::KnownPair> pairs{sdes::KnownPair{plaintext, ciphertext}};
    const sdes::BruteForceResult result = sdes::bruteForceKey(pairs);

    std::cout << "  时间戳 开始     = " << formatTimestamp(result.stats.startedAt) << "\n";
    std::cout << "  时间戳 结束     = " << formatTimestamp(result.stats.finishedAt) << "\n";
    std::cout << "  工作线程数      = " << result.stats.workerThreads << "\n";
    std::cout << "  遍历密钥数      = " << result.stats.keysTested << " / " << result.stats.keySpaceSize
              << "\n";
    std::cout << "  总耗时          = " << std::fixed << std::setprecision(3)
              << result.stats.elapsedMilliseconds() << " 毫秒  ("
              << std::setprecision(0) << result.stats.elapsedMicroseconds() << " 微秒)\n";
    std::cout << "  破解速度        = " << std::fixed << std::setprecision(0)
              << result.stats.keysPerSecond() << " 个密钥/秒\n";
    std::cout << "  命中候选密钥    = " << result.candidateKeys.size() << " 个\n";
    for (const sdes::Block10& candidate : result.candidateKeys) {
        const bool isSecret = (candidate == secretKey);
        std::cout << "      " << candidate.toString() << (isSecret ? "   <- 真实密钥" : "   <- 碰撞密钥（同样能通过验证）")
                  << "\n";
    }

    // 再加一对明密文，观察候选范围如何收缩
    const sdes::Block8 secondPlaintext = sdes::Block8::fromString("00001111");
    const std::vector<sdes::KnownPair> twoPairs{pairs.front(),
                                                sdes::KnownPair{secondPlaintext, secretCipher.encrypt(secondPlaintext)}};
    const sdes::BruteForceResult narrowed = sdes::bruteForceKey(twoPairs);
    std::cout << "\n  再增加一对明密文 (" << secondPlaintext.toString() << " -> "
              << secretCipher.encrypt(secondPlaintext).toString() << ") 后：\n";
    std::cout << "  命中候选密钥    = " << narrowed.candidateKeys.size() << " 个   (耗时 "
              << std::fixed << std::setprecision(3) << narrowed.stats.elapsedMilliseconds() << " 毫秒)\n";
    for (const sdes::Block10& candidate : narrowed.candidateKeys) {
        std::cout << "      " << candidate.toString() << (candidate == secretKey ? "   <- 真实密钥" : "") << "\n";
    }
}

// =============================================================================
//  第 5 关：密钥空间结构
// =============================================================================

void printStage5(const RuntimeConfig& config) {
    std::cout << "\n【第 5 关】封闭测试 —— 是否存在多个密钥对应同一密文\n";
    std::cout << rule() << "\n";

    const sdes::Block8 plaintext = sdes::Block8::fromString("10010111");
    const sdes::PlaintextAnalysis analysis = sdes::analysePlaintext(plaintext, config.mode);

    std::cout << "  固定明文 P = " << plaintext.toString() << "，穷举全部 1024 个密钥：\n\n";
    std::cout << "  不同密文个数             = " << analysis.distinctCiphertexts << " / 256\n";
    std::cout << "  只对应 1 个密钥的密文    = " << analysis.singleKeyCiphertexts << "\n";
    std::cout << "  对应 >=2 个密钥的密文    = " << analysis.collidingCiphertexts << "\n";
    std::cout << "  落在碰撞里的密钥数       = " << analysis.keysInCollisions << " / 1024\n";
    std::cout << "  单个密文最多对应密钥数   = " << analysis.maxKeysPerCiphertext << "\n";
    std::cout << "  平均每个密文对应密钥数   = " << std::fixed << std::setprecision(3)
              << analysis.averageKeysPerCiphertext << "\n";
    std::cout << "  最拥挤的密文             = " << analysis.mostCommonCiphertext.toString() << "（对应 "
              << analysis.mostCommonKeys.size() << " 个密钥）\n";

    std::cout << "\n  明文 " << plaintext.toString() << " -> " << analysis.mostCommonCiphertext.toString()
              << " 的全部密钥：\n";
    for (const sdes::Block10& key : analysis.mostCommonKeys) {
        std::cout << "      " << key.toString() << "\n";
    }

    std::cout << "\n  【结论】\n";
    std::cout << "    (1) 对同一对明密文，确实存在不止一个密钥：上面 "
              << analysis.mostCommonKeys.size() << " 个密钥都能把 " << plaintext.toString() << " 加密成 "
              << analysis.mostCommonCiphertext.toString() << "。\n";
    std::cout << "    (2) 对任意固定明文，不同密钥加密得到相同密文的情形必然存在：\n";
    std::cout << "        1024 个密钥只能产生 " << analysis.distinctCiphertexts
              << " 种密文，按鸽巢原理必然发生碰撞。\n";
    std::cout << "    (3) 但这不等于「密钥等价」：进一步分析见 keyspace 子命令。\n";
}

// =============================================================================
//  第 5 关扩展：整个密钥空间的结构
// =============================================================================

void printKeySpace(const RuntimeConfig& config) {
    std::cout << "密钥空间整体结构分析（对全部 256 种明文穷举 1024 个密钥）\n";
    std::cout << rule() << "\n";

    std::vector<sdes::EquivalentKeyClass> classes;
    const sdes::KeySpaceAnalysis space = sdes::analyseKeySpace(classes, config.mode);

    std::cout << "  密钥扩展读法             = " << sdes::describeKeyScheduleMode(config.mode) << "\n";
    std::cout << "  密钥总数                 = " << space.keySpaceSize << "\n";
    std::cout << "  不同 (k1,k2) 组合数      = " << space.distinctRoundKeyPairs << "\n";
    std::cout << "  不同加密映射个数         = " << space.distinctPermutations << "\n";
    std::cout << "  单元素等价类个数         = " << space.trivialClassCount << "\n";
    std::cout << "  多元素等价类个数         = " << space.nontrivialClassCount << "\n";
    std::cout << "  最大等价类大小           = " << space.largestClassSize << "\n";
    std::cout << "  平均等价类大小           = " << std::fixed << std::setprecision(4)
              << space.averageClassSize << "\n";
    std::cout << "  有效密钥位数             = " << space.effectiveKeyBits << " bit\n";
    std::cout << "  分析耗时                 = " << std::fixed << std::setprecision(1) << space.elapsedMs
              << " 毫秒\n";

    if (space.nontrivialClassCount > 0) {
        std::cout << "\n  多元素等价类示例（这些密钥对任意明文的结果都完全相同）：\n";
        std::size_t shown = 0;
        for (const sdes::EquivalentKeyClass& keyClass : classes) {
            if (keyClass.keys.size() < 2) {
                continue;
            }
            std::cout << "      { ";
            for (const sdes::Block10& key : keyClass.keys) {
                std::cout << key.toString() << " ";
            }
            std::cout << "}\n";
            if (++shown >= 5) {
                std::cout << "      ...（共 " << space.nontrivialClassCount << " 个多元素类）\n";
                break;
            }
        }
    }
}

// =============================================================================
//  demo：一键跑完五关
// =============================================================================

void printHeader(const RuntimeConfig& config) {
    std::cout << "============================================================================\n";
    std::cout << "  S-DES 加解密程序 · 作业演示\n";
    std::cout << "  课程：信息安全导论 · 第 5 次课\n";
    std::cout << "============================================================================\n";
    std::cout << "  分组长度      = 8 bit\n";
    std::cout << "  密钥长度      = 10 bit（密钥空间 1024）\n";
    std::cout << "  密钥扩展读法  = " << sdes::describeKeyScheduleMode(config.mode) << "\n";
    std::cout << "  S 盒版本      = " << describeSBoxSet(config.sBoxes) << "\n";
    std::cout << "  运行时刻      = " << formatTimestamp(std::chrono::system_clock::now()) << "\n";
    std::cout << "============================================================================\n";
}

int runDemo(const RuntimeConfig& config) {
    printHeader(config);
    printStage1(config);
    printStage2(config);
    printStage3(config);
    printStage4(config);
    printStage5(config);

    std::cout << "\n【第 5 关 · 扩展】密钥空间整体结构\n";
    std::cout << rule() << "\n";
    printKeySpace(config);

    std::cout << "\n============================================================================\n";
    std::cout << "  演示结束\n";
    std::cout << "============================================================================\n";
    return 0;
}

// =============================================================================
//  各子命令
// =============================================================================

int runEncryptOrDecrypt(const ArgumentParser& parser, const RuntimeConfig& config, bool decryptMode) {
    std::string error;
    if (!parser.has("key")) {
        std::cerr << "错误：缺少 --key\n";
        return 2;
    }
    if (!parser.has("input")) {
        std::cerr << "错误：缺少 --input\n";
        return 2;
    }

    const std::optional<sdes::Block10> key = readKey(parser.get("key"), error);
    if (!key.has_value()) {
        std::cerr << "错误：" << error << "\n";
        return 2;
    }
    const std::optional<sdes::Block8> input = readBlock(parser.get("input"), error);
    if (!input.has_value()) {
        std::cerr << "错误：" << error << "\n";
        return 2;
    }

    const sdes::Cipher cipher = config.makeCipher(*key);
    std::cout << "密钥扩展读法：" << sdes::describeKeyScheduleMode(config.mode) << "\n";
    std::cout << "S 盒版本：" << describeSBoxSet(config.sBoxes) << "\n\n";
    printKeySchedule(cipher);

    std::cout << "\n";
    const sdes::CipherTrace trace = decryptMode ? cipher.traceDecrypt(*input) : cipher.traceEncrypt(*input);
    printCipherTrace(trace);

    std::cout << "\n" << (decryptMode ? "解密结果" : "加密结果") << " = " << trace.output.toString() << "\n";
    return 0;
}

int runText(const ArgumentParser& parser, const RuntimeConfig& config) {
    std::string error;
    if (!parser.has("key")) {
        std::cerr << "错误：缺少 --key\n";
        return 2;
    }
    const std::optional<sdes::Block10> key = readKey(parser.get("key"), error);
    if (!key.has_value()) {
        std::cerr << "错误：" << error << "\n";
        return 2;
    }
    const sdes::Cipher cipher = config.makeCipher(*key);

    if (parser.has("encrypt")) {
        const std::string plaintext = parser.get("encrypt");
        const std::string ciphertext = cipher.encryptText(plaintext);
        std::cout << "明文            = " << plaintext << "\n";
        std::cout << "密文（十六进制）= " << toHex(ciphertext) << "\n";
        std::cout << "密文（可显示化）= " << toPrintable(ciphertext) << "\n";
        return 0;
    }
    if (parser.has("decrypt")) {
        const std::optional<std::string> ciphertext = fromHex(parser.get("decrypt"));
        if (!ciphertext.has_value()) {
            std::cerr << "错误：--decrypt 的值必须是偶数长度的十六进制串\n";
            return 2;
        }
        std::cout << "密文（十六进制）= " << toHex(*ciphertext) << "\n";
        std::cout << "解密结果        = " << cipher.decryptText(*ciphertext) << "\n";
        return 0;
    }

    std::cerr << "错误：请给出 --encrypt \"文本\" 或 --decrypt <十六进制>\n";
    return 2;
}

int runBrute(const ArgumentParser& parser, const RuntimeConfig& config) {
    std::vector<sdes::KnownPair> pairs;
    std::string error;

    for (const std::string& pairText : parser.getAll("pair")) {
        const std::size_t separator = pairText.find(':');
        if (separator == std::string::npos) {
            std::cerr << "错误：--pair 的格式应为 明文:密文，例如 10010111:00111000\n";
            return 2;
        }
        const std::optional<sdes::Block8> plaintext =
            readBlock(pairText.substr(0, separator), error);
        const std::optional<sdes::Block8> ciphertext =
            readBlock(pairText.substr(separator + 1), error);
        if (!plaintext.has_value() || !ciphertext.has_value()) {
            std::cerr << "错误：" << error << "\n";
            return 2;
        }
        pairs.push_back(sdes::KnownPair{*plaintext, *ciphertext});
    }

    if (pairs.empty()) {
        std::cerr << "错误：至少需要一对 --pair 明文:密文\n";
        return 2;
    }

    sdes::BruteForceOptions options;
    options.keyScheduleMode = config.mode;
    if (parser.has("threads")) {
        try {
            options.workerThreads = static_cast<unsigned>(std::stoul(parser.get("threads")));
        } catch (const std::exception&) {
            std::cerr << "错误：--threads 需要一个整数\n";
            return 2;
        }
    }

    std::cout << "暴力破解中…（密钥空间 " << sdes::kKeySpaceSize << "）\n";
    const sdes::BruteForceResult result = sdes::bruteForceKey(pairs, options);

    std::cout << "  时间戳 开始     = " << formatTimestamp(result.stats.startedAt) << "\n";
    std::cout << "  时间戳 结束     = " << formatTimestamp(result.stats.finishedAt) << "\n";
    std::cout << "  工作线程数      = " << result.stats.workerThreads << "\n";
    std::cout << "  遍历密钥数      = " << result.stats.keysTested << " / " << result.stats.keySpaceSize
              << "\n";
    std::cout << "  总耗时          = " << std::fixed << std::setprecision(3)
              << result.stats.elapsedMilliseconds() << " 毫秒\n";
    std::cout << "  命中候选密钥    = " << result.candidateKeys.size() << " 个\n";
    for (const sdes::Block10& key : result.candidateKeys) {
        std::cout << "      " << key.toString() << "\n";
    }
    return 0;
}

int runAnalyse(const ArgumentParser& parser, const RuntimeConfig& config) {
    std::string error;
    if (!parser.has("plain")) {
        std::cerr << "错误：缺少 --plain（8 bit 明文分组）\n";
        return 2;
    }
    const std::optional<sdes::Block8> plaintext = readBlock(parser.get("plain"), error);
    if (!plaintext.has_value()) {
        std::cerr << "错误：" << error << "\n";
        return 2;
    }

    const sdes::PlaintextAnalysis analysis = sdes::analysePlaintext(*plaintext, config.mode);
    std::cout << "固定明文 " << analysis.plaintext.toString() << "，穷举 1024 个密钥：\n";
    std::cout << "  不同密文个数             = " << analysis.distinctCiphertexts << " / 256\n";
    std::cout << "  只对应 1 个密钥的密文    = " << analysis.singleKeyCiphertexts << "\n";
    std::cout << "  对应 >=2 个密钥的密文    = " << analysis.collidingCiphertexts << "\n";
    std::cout << "  单个密文最多对应密钥数   = " << analysis.maxKeysPerCiphertext << "\n";
    std::cout << "  平均每个密文对应密钥数   = " << std::fixed << std::setprecision(3)
              << analysis.averageKeysPerCiphertext << "\n";
    std::cout << "  最拥挤的密文             = " << analysis.mostCommonCiphertext.toString() << "\n";
    std::cout << "  分析耗时                 = " << std::fixed << std::setprecision(2) << analysis.elapsedMs
              << " 毫秒\n";
    return 0;
}

int runVectors(const RuntimeConfig& config) {
    printStage2(config);
    return 0;
}

void printUsage() {
    std::cout << "S-DES 命令行工具 —— 用法\n";
    std::cout << rule() << "\n";
    std::cout << "  sdes-cli demo                                  一键演示全部五关\n";
    std::cout << "  sdes-cli vectors                               输出交叉测试向量表\n";
    std::cout << "  sdes-cli encrypt --key <10bit> --input <8bit>  加密单个分组\n";
    std::cout << "  sdes-cli decrypt --key <10bit> --input <8bit>  解密单个分组\n";
    std::cout << "  sdes-cli text --key <10bit> --encrypt \"文本\"    加密字符串\n";
    std::cout << "  sdes-cli text --key <10bit> --decrypt <hex>    解密字符串（十六进制输入）\n";
    std::cout << "  sdes-cli brute --pair <明文>:<密文> [--threads N]\n";
    std::cout << "  sdes-cli analyse --plain <8bit>                第 5 关：单明文密钥碰撞\n";
    std::cout << "  sdes-cli keyspace                              第 5 关：密钥空间整体结构\n";
    std::cout << "  sdes-cli                                       （不带参数）进入交互式菜单\n";
    std::cout << "\n  通用选项：\n";
    std::cout << "    --mode textbook|literal   密钥扩展读法（默认 textbook）\n";
    std::cout << "    --sbox homework|textbook  S 盒版本（默认 homework）\n";
}

// =============================================================================
//  交互式菜单
// =============================================================================

std::string readLine(const std::string& prompt) {
    std::cout << prompt;
    std::string line;
    if (!std::getline(std::cin, line)) {
        return {};
    }
    // 去掉两端空白
    const std::size_t first = line.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }
    const std::size_t last = line.find_last_not_of(" \t\r\n");
    return line.substr(first, last - first + 1);
}

void menuEncryptOrDecrypt(const RuntimeConfig& config, bool decryptMode) {
    const std::string keyText = readLine("请输入 10 bit 密钥（直接回车用默认 1010000010）：");
    std::string error;
    const std::optional<sdes::Block10> key =
        readKey(keyText.empty() ? "1010000010" : keyText, error);
    if (!key.has_value()) {
        std::cout << "输入有误：" << error << "\n";
        return;
    }

    const std::string blockText =
        readLine(std::string("请输入 8 bit ") + (decryptMode ? "密文" : "明文") + "（直接回车用默认 10010111）：");
    const std::optional<sdes::Block8> block =
        readBlock(blockText.empty() ? "10010111" : blockText, error);
    if (!block.has_value()) {
        std::cout << "输入有误：" << error << "\n";
        return;
    }

    const sdes::Cipher cipher = config.makeCipher(*key);
    std::cout << "\n";
    printKeySchedule(cipher);
    std::cout << "\n";
    const sdes::CipherTrace trace = decryptMode ? cipher.traceDecrypt(*block) : cipher.traceEncrypt(*block);
    printCipherTrace(trace);
    std::cout << "\n" << (decryptMode ? "解密结果" : "加密结果") << " = " << trace.output.toString() << "\n";
}

void menuText(const RuntimeConfig& config, bool decryptMode) {
    const std::string keyText = readLine("请输入 10 bit 密钥（直接回车用默认 1010000010）：");
    std::string error;
    const std::optional<sdes::Block10> key = readKey(keyText.empty() ? "1010000010" : keyText, error);
    if (!key.has_value()) {
        std::cout << "输入有误：" << error << "\n";
        return;
    }
    const sdes::Cipher cipher = config.makeCipher(*key);

    if (decryptMode) {
        const std::string input = readLine("请输入密文的十六进制：");
        const std::optional<std::string> bytes = fromHex(input);
        if (!bytes.has_value()) {
            std::cout << "输入有误：需要偶数长度的十六进制串\n";
            return;
        }
        std::cout << "解密结果 = " << cipher.decryptText(*bytes) << "\n";
    } else {
        const std::string input = readLine("请输入要加密的文本：");
        const std::string ciphertext = cipher.encryptText(input);
        std::cout << "密文（十六进制）= " << toHex(ciphertext) << "\n";
        std::cout << "密文（可显示化）= " << toPrintable(ciphertext) << "\n";
    }
}

void menuBrute(const RuntimeConfig& config) {
    const std::string pairText = readLine("请输入明密文对（格式 明文:密文，回车跳过）：");
    if (pairText.empty()) {
        return;
    }
    const std::size_t separator = pairText.find(':');
    if (separator == std::string::npos) {
        std::cout << "格式错误，应为 10010111:00111000\n";
        return;
    }

    std::string error;
    const std::optional<sdes::Block8> plaintext = readBlock(pairText.substr(0, separator), error);
    const std::optional<sdes::Block8> ciphertext = readBlock(pairText.substr(separator + 1), error);
    if (!plaintext.has_value() || !ciphertext.has_value()) {
        std::cout << "输入有误：" << error << "\n";
        return;
    }

    sdes::BruteForceOptions options;
    options.keyScheduleMode = config.mode;
    options.onProgress = [](std::size_t tested, std::size_t total) {
        std::cout << "\r  进度 " << tested << " / " << total << std::flush;
    };

    std::cout << "暴力破解中…\n";
    const sdes::BruteForceResult result =
        sdes::bruteForceKey(std::vector<sdes::KnownPair>{sdes::KnownPair{*plaintext, *ciphertext}}, options);
    std::cout << "\r";
    std::cout << "  总耗时          = " << std::fixed << std::setprecision(3)
              << result.stats.elapsedMilliseconds() << " 毫秒\n";
    std::cout << "  工作线程数      = " << result.stats.workerThreads << "\n";
    std::cout << "  命中候选密钥    = " << result.candidateKeys.size() << " 个\n";
    for (const sdes::Block10& key : result.candidateKeys) {
        std::cout << "      " << key.toString() << "\n";
    }
}

int runInteractiveMenu(RuntimeConfig config) {
    printHeader(config);

    for (;;) {
        std::cout << "\n" << rule() << "\n";
        std::cout << "  1) 加密一个 8 bit 分组      5) 暴力破解（由明密文对反推密钥）\n";
        std::cout << "  2) 解密一个 8 bit 分组      6) 固定明文的密钥碰撞分析\n";
        std::cout << "  3) 加密字符串               7) 密钥空间整体结构\n";
        std::cout << "  4) 解密字符串               8) 完整演示（五关）\n";
        std::cout << "  9) 切换密钥扩展读法         0) 退出\n";
        std::cout << rule() << "\n";

        const std::string choice = readLine("请选择：");
        if (choice.empty()) {
            continue;
        }

        if (choice == "0" || choice == "exit" || choice == "quit") {
            std::cout << "再见。\n";
            return 0;
        }
        if (choice == "1") {
            menuEncryptOrDecrypt(config, false);
        } else if (choice == "2") {
            menuEncryptOrDecrypt(config, true);
        } else if (choice == "3") {
            menuText(config, false);
        } else if (choice == "4") {
            menuText(config, true);
        } else if (choice == "5") {
            menuBrute(config);
        } else if (choice == "6") {
            const std::string input = readLine("请输入 8 bit 明文（回车用默认 10010111）：");
            std::string error;
            const std::optional<sdes::Block8> plaintext =
                readBlock(input.empty() ? "10010111" : input, error);
            if (!plaintext.has_value()) {
                std::cout << "输入有误：" << error << "\n";
            } else {
                const sdes::PlaintextAnalysis analysis = sdes::analysePlaintext(*plaintext, config.mode);
                std::cout << "  不同密文个数 = " << analysis.distinctCiphertexts << " / 256\n";
                std::cout << "  最拥挤的密文 = " << analysis.mostCommonCiphertext.toString() << "（对应 "
                          << analysis.maxKeysPerCiphertext << " 个密钥）\n";
                std::cout << "  平均对应密钥 = " << std::fixed << std::setprecision(3)
                          << analysis.averageKeysPerCiphertext << "\n";
            }
        } else if (choice == "7") {
            printKeySpace(config);
        } else if (choice == "8") {
            runDemo(config);
        } else if (choice == "9") {
            config.mode = (config.mode == sdes::KeyScheduleMode::TextbookProgressive)
                              ? sdes::KeyScheduleMode::LiteralFormula
                              : sdes::KeyScheduleMode::TextbookProgressive;
            std::cout << "已切换为：" << sdes::describeKeyScheduleMode(config.mode) << "\n";
        } else {
            std::cout << "无效选择。\n";
        }
    }
}

}  // namespace

int main(int argc, char** argv) {
#if defined(_WIN32)
    // 让控制台按 UTF-8 显示中文
    SetConsoleOutputCP(CP_UTF8);
#endif

    const std::vector<std::string> arguments(argv + 1, argv + argc);
    if (arguments.empty()) {
        return runInteractiveMenu(RuntimeConfig{});
    }

    const std::string command = arguments.front();
    const ArgumentParser parser(std::vector<std::string>(arguments.begin() + 1, arguments.end()));

    RuntimeConfig config;
    std::string error;
    if (!applyRuntimeOptions(parser, config, error)) {
        std::cerr << "错误：" << error << "\n";
        return 2;
    }

    try {
        if (command == "demo") {
            return runDemo(config);
        }
        if (command == "vectors") {
            return runVectors(config);
        }
        if (command == "encrypt") {
            return runEncryptOrDecrypt(parser, config, false);
        }
        if (command == "decrypt") {
            return runEncryptOrDecrypt(parser, config, true);
        }
        if (command == "text") {
            return runText(parser, config);
        }
        if (command == "brute") {
            return runBrute(parser, config);
        }
        if (command == "analyse" || command == "analyze") {
            return runAnalyse(parser, config);
        }
        if (command == "keyspace") {
            printKeySpace(config);
            return 0;
        }
        if (command == "help" || command == "--help" || command == "-h") {
            printUsage();
            return 0;
        }

        std::cerr << "未知子命令：" << command << "\n\n";
        printUsage();
        return 2;
    } catch (const std::exception& exception) {
        std::cerr << "运行出错：" << exception.what() << "\n";
        return 1;
    }
}
