# 开发手册

本文档说明工程的结构、核心数据表示约定，以及各组件的接口，供后续维护或在此基础上扩展的人参考。

---

## 1. 设计目标与分层

```
        ┌──────────────────────────────┐
        │  apps/gui    Qt 6 图形界面    │  ← 只负责界面与交互
        ├──────────────────────────────┤
        │  apps/cli    命令行前端       │  ← 只负责参数解析与结果排版
        ├──────────────────────────────┤
        │  include/sdes + src           │  ← 纯 C++17，零第三方依赖
        │  · bit_block  · tables        │
        │  · key_schedule · cipher      │
        │  · brute_force  · analysis    │
        └──────────────────────────────┘
```

三条设计原则：

1. **算法核心不依赖任何界面框架。** 核心库只用标准库，所以它既可以被 Qt 界面调用，也能被命令行调用，还能用 `g++` 单独编译测试。
2. **算法参数不写死。** S 盒有两套（作业版 / 教材版）、密钥扩展有两种读法，都通过参数传入，而不是 `#define` 或全局变量。这样同一份代码既能跑作业标准，也能用来做自证。
3. **每一步都留下可观测的中间量。** 密钥扩展和两轮 Feistel 都提供带 trace 的版本，界面与命令行据此展示完整过程。位运算算法如果只暴露最终结果，出错时很难定位。

---

## 2. 位序约定（读代码前必看）

这是整个工程最需要先说清楚的一条：

> **`BitBlock<N>` 内部的索引 `0` 表示位串「最左侧」的那一位（最高有效位）。**

于是作业里给出的置换表可以**原样照抄**，不需要做任何下标变换：

```cpp
// P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6) 表示「输出第 1 位取自输入第 3 位」
template <std::size_t InN, std::size_t OutN>
BitBlock<OutN> permute(const BitBlock<InN>& input, const PermutationTable<OutN>& table) {
    BitBlock<OutN> output;
    for (std::size_t i = 0; i < OutN; ++i) {
        const int source = table[i];              // 1-based，直接来自作业定义
        output.set(i, input.at(static_cast<std::size_t>(source) - 1));
    }
    return output;
}
```

举例：

```cpp
const BitBlock<8> block = BitBlock<8>::fromString("10010111");
block.at(0)  // true  —— 最左边的 1
block.at(1)  // false
block.at(3)  // true  —— 从左数第 4 位
block.at(7)  // true  —— 最右边的 1
block.toUint()  // 0x97
```

同时 `permute` 是**变长**的：`EP` 是 4→8（扩展），`P8` 是 10→8（压缩），`IP` / `IP⁻¹` 是 8→8，都由模板参数自动推导。

---

## 3. 接口文档

### 3.1 `sdes::BitBlock<N>`（`include/sdes/bit_block.hpp`）

定长位串，长度在编译期确定。

```cpp
template <std::size_t N> class BitBlock {
public:
    static constexpr std::size_t kSize = N;

    BitBlock() noexcept;                                        // 全 0

    // 构造 / 解析
    static BitBlock fromString(std::string_view text);          // 解析失败抛 std::invalid_argument
    static std::optional<BitBlock> tryFromString(std::string_view text) noexcept;
    static BitBlock fromUint(std::uint32_t value);              // 高位对齐

    // 访问（越界抛 std::out_of_range）
    bool at(std::size_t index) const;
    void set(std::size_t index, bool value);

    // 转换
    std::string toString() const;                               // "1010000010"，长度恰为 N
    std::uint32_t toUint() const noexcept;

    // 运算
    BitBlock operator^(const BitBlock&) const noexcept;         // 逐位异或
    BitBlock& operator^=(const BitBlock&) noexcept;
    BitBlock operator~() const noexcept;
    bool operator==/!=/<(...) const noexcept;
    BitBlock rotateLeft(std::size_t count) const noexcept;      // 循环左移

    // 拆分与拼接
    std::pair<BitBlock<N/2>, BitBlock<N/2>> split() const;      // 要求 N 为偶数
    static BitBlock concat(const BitBlock<N/2>& left, const BitBlock<N/2>& right);
};

// 长度别名
using Block2 = BitBlock<2>;   using Block4  = BitBlock<4>;
using Block5 = BitBlock<5>;   using Block8  = BitBlock<8>;
using Block10 = BitBlock<10>;

// 置换
template <std::size_t InN, std::size_t OutN>
BitBlock<OutN> permute(const BitBlock<InN>& input, const PermutationTable<OutN>& table);

// 8 bit 分组 <-> 字节（第 3 关逐字节处理时使用）
inline Block8 blockFromByte(unsigned char value) noexcept;
inline unsigned char byteFromBlock(const Block8& block) noexcept;
```

`fromString` 的宽松之处：长度不足 `N` 时**在左侧补零**（方便手工输入 `101` 表示 `00000101`），两端空白会被忽略；超长或含非 `0/1` 字符则解析失败。

### 3.2 转换装置常数表（`include/sdes/tables.hpp`）

```cpp
namespace sdes::tables {
inline constexpr PermutationTable<10> kP10{3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
inline constexpr PermutationTable<8>  kP8 {6, 3, 7, 4, 8, 5, 10, 9};
inline constexpr PermutationTable<5>  kLeftShift1{2, 3, 4, 5, 1};
inline constexpr PermutationTable<5>  kLeftShift2{3, 4, 5, 1, 2};
inline constexpr PermutationTable<8>  kIP {2, 6, 3, 1, 4, 8, 5, 7};
inline constexpr PermutationTable<8>  kIPInverse{4, 1, 3, 5, 7, 2, 8, 6};
inline constexpr PermutationTable<8>  kEP {4, 1, 2, 3, 2, 3, 4, 1};
inline constexpr PermutationTable<4>  kSP {2, 4, 3, 1};

using SBoxTable = std::array<std::array<int, 4>, 4>;

inline constexpr SBoxTable kSBox1{{ {1,0,3,2}, {3,2,1,0}, {0,2,1,3}, {3,1,0,2} }};
inline constexpr SBoxTable kSBox2{{ {0,1,2,3}, {2,3,1,0}, {3,0,1,2}, {2,1,0,3} }};          // 作业指定
inline constexpr SBoxTable kSBox2Textbook{{ {0,1,2,3}, {2,0,1,3}, {3,0,1,0}, {2,1,0,3} }};  // 教材原始，仅自检用
}
```

`kLeftShift1` / `kLeftShift2` 保留成表的形式，是为了能和作业给出的 `Left_Shift^1` / `Left_Shift^2` 定义**逐项对照**（测试里就有一项验证它们与 `rotateLeft(1)` / `rotateLeft(2)` 等价）。

### 3.3 `sdes::SBoxSet`（`include/sdes/tables.hpp`）

```cpp
struct SBoxSet {
    const tables::SBoxTable* sBox1 = &tables::kSBox1;
    const tables::SBoxTable* sBox2 = &tables::kSBox2;

    static constexpr SBoxSet homework() noexcept;   // 作业指定版本（默认）
    static constexpr SBoxSet textbook() noexcept;   // Schneier 教材原始版本

    const tables::SBoxTable& s1() const noexcept;
    const tables::SBoxTable& s2() const noexcept;
};
```

### 3.4 密钥扩展（`include/sdes/key_schedule.hpp`）

```cpp
enum class KeyScheduleMode {
    TextbookProgressive,   // k2 在 k1 的状态上再左移 2 位（累计 3 位）—— 默认
    LiteralFormula,        // k2 对 P10(K) 直接左移 2 位
};

inline constexpr KeyScheduleMode kDefaultKeyScheduleMode = KeyScheduleMode::TextbookProgressive;

struct RoundKeys { Block8 k1; Block8 k2; };

RoundKeys deriveRoundKeys(const Block10& masterKey,
                          KeyScheduleMode mode = kDefaultKeyScheduleMode);

/// 带中间过程
struct KeyScheduleTrace {
    Block10 masterKey;
    KeyScheduleMode mode;
    Block10 afterP10;
    Block5  leftAfterShift1, rightAfterShift1;   Block10 afterShift1;
    Block5  leftAfterShift2, rightAfterShift2;   Block10 afterShift2;
    Block8  k1, k2;
};
KeyScheduleTrace traceKeySchedule(const Block10& masterKey,
                                  KeyScheduleMode mode = kDefaultKeyScheduleMode);

const char* describeKeyScheduleMode(KeyScheduleMode mode) noexcept;
```

**为什么会有两种读法**：作业公式 `k_i = P₈(Shiftⁱ(P₁₀(K)))` 既可理解成「对 `P₁₀(K)` 移 i 位」（i=2 时移 2 位），也可理解成「第 i 次移位操作」（第一次移 1 位，第二次移 2 位，累计 3 位）。两者只在 `k2` 上不同，却会让密文整体不同。经过验证，只有递进式能复现教材向量、且使 `(k1,k2)` 覆盖密钥的全部 10 位，因此定为默认。详见测试报告。

### 3.5 加解密（`include/sdes/cipher.hpp`）

```cpp
class Cipher {
public:
    explicit Cipher(Block10 masterKey,
                    SBoxSet sBoxes = SBoxSet::homework(),
                    KeyScheduleMode keyScheduleMode = kDefaultKeyScheduleMode);

    Block8 encrypt(Block8 plaintext) const;
    Block8 decrypt(Block8 ciphertext) const;

    CipherTrace traceEncrypt(Block8 plaintext) const;
    CipherTrace traceDecrypt(Block8 ciphertext) const;

    // 第 3 关：按 1 Byte 分组处理任意文本
    std::string encryptText(std::string_view plaintext) const;
    std::string decryptText(std::string_view ciphertext) const;

    const Block10& masterKey() const noexcept;
    const RoundKeys& roundKeys() const noexcept;
    const SBoxSet& sBoxes() const noexcept;
    KeyScheduleMode keyScheduleMode() const noexcept;

    // 供测试与界面复用的公开静态成员
    static Block4 feistelFunction(const Block4& rightHalf, const Block8& roundKey, const SBoxSet&);
    static Block8 swapHalves(const Block8& block) noexcept;
};

/// S 盒替换：行号 = 输入第 1、4 位，列号 = 第 2、3 位，输出 2 bit
Block2 applySBox(const Block4& input, const tables::SBoxTable& sBox);
```

`CipherTrace` 记录了从 `IP` 到 `IP⁻¹` 的全部中间量（两轮各自的 L/R、轮密钥、`f` 输出、`SW` 前后），界面和命令行用它渲染逐步过程。

加解密是对称的，唯一差别是轮密钥使用顺序：

```cpp
Block8 Cipher::encrypt(Block8 plaintext) const {
    const Block8 afterIP     = permute(plaintext, tables::kIP);
    const Block8 afterRound1 = feistelRound(afterIP,        roundKeys_.k1, sBoxes_);
    const Block8 afterSwap   = swapHalves(afterRound1);
    const Block8 afterRound2 = feistelRound(afterSwap,      roundKeys_.k2, sBoxes_);
    return permute(afterRound2, tables::kIPInverse);
}
```

### 3.6 暴力破解（`include/sdes/brute_force.hpp`）—— 第 4 关

```cpp
struct KnownPair { Block8 plaintext; Block8 ciphertext; };

struct BruteForceStats {
    std::size_t keysTested, keySpaceSize;
    unsigned workerThreads;
    std::chrono::steady_clock::duration totalDuration;
    std::chrono::system_clock::time_point startedAt, finishedAt;

    double elapsedSeconds() const;
    double elapsedMilliseconds() const;
    double elapsedMicroseconds() const;
    double keysPerSecond() const;
};

struct BruteForceResult {
    std::vector<Block10> candidateKeys;   // 全部满足条件的密钥，升序
    BruteForceStats stats;
};

using BruteForceProgress = std::function<void(std::size_t tested, std::size_t total)>;

struct BruteForceOptions {
    unsigned workerThreads = 0;                                  // 0 = 按硬件并发度自动
    KeyScheduleMode keyScheduleMode = kDefaultKeyScheduleMode;   // 必须与实际加密时一致
    BruteForceProgress onProgress;                               // 可为空
};

BruteForceResult bruteForceKey(const std::vector<KnownPair>& pairs, BruteForceOptions options = {});

/// 单线程对照实现，用于验证多线程结果一致
BruteForceResult bruteForceKeySingleThreaded(const std::vector<KnownPair>& pairs,
                                             KeyScheduleMode = kDefaultKeyScheduleMode);

inline constexpr std::size_t kKeySpaceSize = std::size_t{1} << 10;   // 1024
```

**并发模型**：把密钥空间切成 16 个一组的小块，每个工作线程用 `std::atomic` 抢下一块（`nextChunk.fetch_add`）。这样不需要预先划分区间，也不会因为某个区间的密钥「碰巧更容易命中」而导致线程间负载不均。命中结果用 `std::mutex` 保护后写入。

**进度回调的线程安全**：`onProgress` 会在**多个工作线程里**被调用。CLI 直接打印（够快），Qt 侧则用 `emit` 把信号发回主线程（跨线程 `emit` 自动排队投递）。**调用方必须自己保证线程安全**。

### 3.7 密钥空间分析（`include/sdes/analysis.hpp`）—— 第 5 关

```cpp
using CiphertextKeyMap = std::map<Block8, std::vector<Block10>>;

/// 固定明文，穷举 1024 个密钥，得到「密文 -> 密钥列表」
CiphertextKeyMap groupKeysByCiphertext(Block8 plaintext,
                                       KeyScheduleMode = kDefaultKeyScheduleMode);

struct PlaintextAnalysis {
    Block8 plaintext;
    std::size_t keyCount;                 // 1024
    std::size_t distinctCiphertexts;      // 实际出现的不同密文个数
    std::size_t singleKeyCiphertexts;     // 只对应唯一密钥的密文个数
    std::size_t collidingCiphertexts;     // 对应 >= 2 个密钥的密文个数
    std::size_t keysInCollisions;         // 落在碰撞里的密钥个数
    std::size_t maxKeysPerCiphertext;
    double averageKeysPerCiphertext;
    int maxAchievableBits;
    bool coversWholeCipherSpace;
    Block8 mostCommonCiphertext;
    std::vector<Block10> mostCommonKeys;
    double elapsedMs;
};
PlaintextAnalysis analysePlaintext(Block8 plaintext, KeyScheduleMode = kDefaultKeyScheduleMode);

/// 等价密钥类：类中任意两个密钥对全部 256 种明文的加密结果都相同
struct EquivalentKeyClass { std::vector<Block10> keys; };
std::vector<EquivalentKeyClass> findEquivalentKeyClasses(KeyScheduleMode = kDefaultKeyScheduleMode);

struct KeySpaceAnalysis {
    std::size_t keySpaceSize;              // 1024
    std::size_t distinctRoundKeyPairs;     // 不同 (k1,k2) 组合数
    std::size_t distinctPermutations;      // 真正互不相同的加密映射个数
    std::size_t trivialClassCount;         // 单元素等价类个数
    std::size_t nontrivialClassCount;      // 多元素等价类个数
    std::size_t largestClassSize;
    double averageClassSize;
    std::size_t effectiveKeyBits;          // 有效密钥位数
    double elapsedMs;
};
KeySpaceAnalysis analyseKeySpace(std::vector<EquivalentKeyClass>& classesOut,
                                 KeyScheduleMode = kDefaultKeyScheduleMode);
```

**等价性的判定方式**：给每个密钥算一个「行为指纹」—— 它对全部 256 个明文分组的加密结果（256 字节）。指纹相同即两个密钥在外部观测上完全不可区分。整轮计算量是 1024 × 256 ≈ 26 万次加密，实测约 20 毫秒。

---

## 4. 编码规范落实情况

对照作业「代码规范」一节：

### 4.1 变量命名

统一使用 `snake_case`（`master_key`、`round_key`）与 `CamelCase`（类名 `BitBlock`、`Cipher`、`BruteForceResult`）。禁止单字母变量名，连循环下标也写成 `index` / `row` / `column`。布尔量以 `is` / `has` / `can` 开头（`isRunning`、`hasValue`）。

### 4.2 代码注释

只给**不显然**的地方写注释，重点解释三件事：

- **为什么**这么做（例如 `brute_force.cpp` 里 `kKeyChunkSize = 16` 的取值理由）
- **位序、边界、约定**这类容易踩坑的细节
- 与作业定义的对应关系（例如 `tables.hpp` 里每个表都标注它对应作业里的哪个式子）

不给 `int i = 0;  // 把 i 设为 0` 这种废话写注释。

### 4.3 函数式 / 模块化

- 每个小模块只干一件事：`permute` 只做置换，`applySBox` 只做一次 S 盒替换，`feistelFunction` 只做一个轮函数。
- 重复逻辑一律提取：`feistelRound` 被加密和解密共用；`permute` 被所有 8 个置换表共用。
- 构造与计算分离：`Cipher` 构造时完成密钥扩展，`encrypt` / `decrypt` 是纯函数式的 `const` 成员。
- 用标准库而不是手搓容器：`std::array` 存表、`std::optional` 表达可能失败的解析、`std::map` 做密文分组、`std::thread` + `std::atomic` 做并发。

---

## 5. 如何扩展

### 换一套 S 盒

在 `tables.hpp` 里加一张 `SBoxTable` 常量，然后新增一个 `SBoxSet` 工厂：

```cpp
struct SBoxSet {
    static constexpr SBoxSet mine() noexcept { return {&tables::kSBox1, &tables::kMySBox2}; }
};
```

### 换一种位序约定

只需要改 `bit_block.hpp` 里的 `at` / `set` / `permute` / `toString`，其余模块完全不受影响 —— 这正是把位序约定集中在一个文件里的目的。

### 换一套界面配色

图形界面的全部视觉规则集中在 `apps/gui/theme.cpp` 的 `styleSheet()` 里（Qt 样式表），
配色令牌在文件头部注释中列成了一张表。改主题只需要动这一个文件，
界面结构代码（`main_window.cpp`）完全不知道颜色细节。

两个约定值得留意：

- **主操作按钮用动态属性标记**，不靠 `objectName`：

  ```cpp
  button->setProperty("primary", true);   // 对应 QSS 里的 QPushButton[primary="true"]
  ```

  目前由 `applyPageChrome()` 统一给「每页第一个按钮」打上这个标记，
  新增按钮时只要遵守「主操作放最左」就不会漏。

- **等宽区域用 `mono` 属性**标记（位串输入框、中间过程文本框、表格）。
  不能只靠 `setFont()`：全局样式表里的 `font-family` 会把它覆盖掉。

### 加一个新的前端

核心库是纯 C++ 的静态库，任何前端只要 `#include "sdes/cipher.hpp"` 就能用。CMake 里 `target_link_libraries(你的目标 PRIVATE sdes_core)` 即可。

### 把 S-DES 换成 DES

`bit_block.hpp` 的 `BitBlock<N>` 是长度泛化的，`permute` 也是变长的。真正需要改的只有：S 盒换成 8 张 4×16 的表（`applySBox` 需要扩展成接受 6 bit 输入、输出 4 bit）、轮数从 2 改成 16、密钥扩展换成 PC-1 / PC-2 的 16 轮循环左移。`Cipher` 的 Feistel 结构本身不用动。

---

## 6. 构建系统

`CMakeLists.txt` 定义了四个目标：

| 目标 | 产物 | 依赖 |
| --- | --- | --- |
| `sdes_core` | `libsdes_core.a` | 只有标准库 + Threads |
| `sdes_tests` | `test-sdes.exe` | `sdes_core` |
| `sdes_cli` | `sdes-cli.exe` | `sdes_core` |
| `sdes_gui` | `sdes-gui.exe` | `sdes_core` + `Qt6::Widgets` |

`find_package(Qt6 QUIET ...)` 用的是 `QUIET`：**没装 Qt 时不会配置失败**，只是跳过图形界面目标，其余目标照常构建。这样助教或同学即使没装 Qt 也能一键构建并跑通全部测试。

编译 Qt 程序必须使用 Qt 自带的那套 MinGW（`C:\Qt\Tools\mingw1310_64`），不能和 w64devkit 的 g++ 混用：两者的 `libstdc++` 版本不同，C++ ABI 不兼容。`scripts\build-gui.ps1` 会自动选中正确的编译器。

构建完成后 `build-gui.ps1` 还会做一次**部署**，把运行时 DLL 拷进 `build-gui\`。这一步不能省：

| DLL | 谁会用到 |
| --- | --- |
| `libstdc++-6.dll`、`libgcc_s_seh-1.dll`、`libwinpthread-1.dll` | **所有**用该工具链编译的 exe，包括不用 Qt 的 `sdes-cli.exe` / `test-sdes.exe` |
| `Qt6Core.dll`、`Qt6Gui.dll`、`Qt6Widgets.dll` 及 `platforms` 等插件 | 只有 `sdes-gui.exe` |

缺 DLL 时 Windows 会让程序以退出码 `0xC0000135`（`STATUS_DLL_NOT_FOUND`）静默退出，没有任何报错信息，排查起来很费时间。可用 `objdump -p sdes-cli.exe | grep "DLL Name"` 查看导入表确认。

两个自定义目标：

```powershell
cmake --build build --target run-tests    # 构建并运行自测程序
ctest --test-dir build                     # 走 ctest
```
