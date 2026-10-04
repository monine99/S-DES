# S-DES 加解密程序

> 信息安全导论 · 第 5 次课作业 —— 用 C++ 实现 S-DES 分组密码的加解密程序

本项目按作业要求实现了 S-DES（Simplified DES）的完整加解密流程，并提供**图形界面**与**命令行**两套前端，覆盖作业的全部五个关卡。

| 项目 | 值 |
| --- | --- |
| 分组长度 | 8 bit |
| 密钥长度 | 10 bit（密钥空间 2¹⁰ = 1024） |
| 加密 | `C = IP⁻¹( f_k2( SW( f_k1( IP(P) ) ) ) )` |
| 解密 | `P = IP⁻¹( f_k1( SW( f_k2( IP(C) ) ) ) )` |
| 密钥扩展 | `k_i = P₈( Shiftⁱ( P₁₀(K) ) )，i = 1, 2` |
| 语言 / 依赖 | C++17；核心算法零依赖，图形界面依赖 Qt 6 |

---

## 快速开始

### 方式一：只有 g++，不需要 Qt（推荐先跑这个）

```powershell
# 在项目根目录下
powershell -ExecutionPolicy Bypass -File scripts\build-cli.ps1

# 跑自动化验收测试（54 项）
.\build\test-sdes.exe

# 一键演示五个关卡
.\build\sdes-cli.exe demo

# 进入交互式菜单
.\build\sdes-cli.exe
```

### 方式二：Qt 6 图形界面

需要先安装 Qt 6（安装步骤见 [用户指南](docs/user-guide.md#安装-qt-6)），然后：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-gui.ps1
.\build-gui\sdes-gui.exe
```

脚本会自动定位 Qt、CMake 和 Ninja，并在构建完成后把运行时 DLL（MinGW 的 `libstdc++-6.dll` 等，加上 Qt 的 `Qt6Core/Qt6Gui/Qt6Widgets` 与插件）一并部署到 `build-gui\`，因此产物可以直接双击运行，也能整目录拷给别人。

也可以直接用 **Qt Creator** 打开项目根目录的 `CMakeLists.txt`，选中 MinGW 套件后一键构建运行。

### 在 VS Code 中

工程已附带 `.vscode/` 配置：

| 操作 | 快捷键 |
| --- | --- |
| 构建（核心库 + CLI + 自测） | `Ctrl+Shift+B` |
| 运行自测程序 | 任务面板 → `运行：自测程序` |
| 运行五关演示 | 任务面板 → `运行：五关演示` |
| 调试 CLI / GUI | `F5`（在运行与调试面板选择对应配置） |

---

## 五个关卡与实现位置

| 关卡 | 内容 | 图形界面 | 命令行 |
| --- | --- | --- | --- |
| 第 1 关 | 基本测试：8 bit 明文 + 10 bit 密钥加解密 | 标签页「1. 基本加解密」 | `sdes-cli encrypt / decrypt` |
| 第 2 关 | 交叉测试：统一算法流程与转换单元 | 标签页「2. 交叉测试」 | `sdes-cli vectors` |
| 第 3 关 | 扩展功能：ASCII 字符串加解密 | 标签页「3. 字符串加解密」 | `sdes-cli text` |
| 第 4 关 | 暴力破解：由明密文对反推密钥（多线程 + 计时） | 标签页「4. 暴力破解」 | `sdes-cli brute` |
| 第 5 关 | 封闭测试：密钥碰撞与密钥空间结构分析 | 标签页「5. 密钥分析」 | `sdes-cli analyse` / `sdes-cli keyspace` |

---

## 目录结构

```
S-DES/
├─ include/sdes/            算法核心库的公开头文件
│   ├─ bit_block.hpp        定长位串类型 + 置换函数（位序约定的唯一来源）
│   ├─ tables.hpp           全部 P-Box / S-Box 常数表
│   ├─ key_schedule.hpp     密钥扩展
│   ├─ cipher.hpp           加解密本体
│   ├─ brute_force.hpp      第 4 关：多线程暴力破解
│   └─ analysis.hpp         第 5 关：密钥空间结构分析
├─ src/                     核心库实现
├─ apps/
│   ├─ cli/main.cpp         命令行前端
│   └─ gui/                 Qt 6 图形界面
├─ tests/test_sdes.cpp      自动化验收测试（54 项）
├─ scripts/
│   ├─ build-cli.ps1        只用 g++ 构建（不需要 Qt）
│   └─ build-gui.ps1        用 CMake + Qt 构建图形界面
├─ docs/
│   ├─ user-guide.md        用户指南
│   ├─ developer-guide.md   开发手册 / 接口文档
│   └─ test-report.md       测试报告
└─ CMakeLists.txt
```

分层原则：**核心算法层完全不依赖 Qt**，图形界面只是一层壳。因此算法可以用 `g++` 单独编译验证，也便于将来替换成别的界面框架。

---

## ⚠ 两个必须注意的标准细节

### 1. S 盒以作业指定版本为准

作业给出的 `SBox₂` 与 Schneier《Applied Cryptography》教材原版不同：

| 行 | 教材原版 S1 | 作业指定 SBox₂ |
| --- | --- | --- |
| 0 | 0 1 2 3 | 0 1 2 3 |
| 1 | 2 **0 1 3** | 2 **3 1 0** |
| 2 | 3 **0 1 0** | 3 **0 1 2** |
| 3 | 2 1 0 3 | 2 1 0 3 |

程序**默认使用作业指定版本**（`--sbox homework`）。教材版本保留下来（`--sbox textbook`）只为一件事：**证明实现正确** —— 用教材版本能精确复现教材经典向量 `K=1010000010, P=10010111 → C=00111000`。

### 2. 密钥扩展公式的两种读法

作业公式 `k_i = P₈(Shiftⁱ(P₁₀(K)))` 有两种解读方式，**它们给出的 k2 不同，会导致密文整体不同**：

| | 教材递进式（**默认**） | 公式字面式 |
| --- | --- | --- |
| k1 | `P₈(LS-1(P₁₀(K)))` | 同左 |
| k2 | `P₈(LS-2(LS-1(P₁₀(K))))`，累计移 3 位 | `P₈(LS-2(P₁₀(K)))`，只移 2 位 |
| K=1010000010 时 k2 | `01000011` | `10010010` |
| 不同 `(k1,k2)` 组合数 | **1024** | 512 |
| 有效密钥位数 | **10 bit** | 9 bit |
| 能否复现教材向量 | 能 | 不能 |

程序默认采用**教材递进式**，理由有三：它与 Schneier 结构图的画法一致（第二个 LS 的箭头从第一个 LS 的输出接出去）；它给出的 `k1=10100100, k2=01000011` 是公认的标准值；而且只有它能让 `(k1, k2)` 覆盖密钥的全部 10 位（字面式会丢掉 1 bit，使 1024 个密钥塌缩成 512 种映射）。

如果交叉测试时发现和同学对不上，先确认双方用的是同一种读法：

```powershell
.\build\sdes-cli.exe vectors --mode textbook   # 教材递进式
.\build\sdes-cli.exe vectors --mode literal    # 公式字面式
```

图形界面里在菜单 **设置 → 密钥扩展读法** 中切换。

---

## 文档

- [用户指南](docs/user-guide.md) —— 安装、构建、界面操作说明
- [开发手册](docs/developer-guide.md) —— 架构、接口文档、数据表示约定
- [测试报告](docs/test-report.md) —— 五关的测试结果与自动化测试结论
