# 用户指南

本文档面向使用者，说明如何构建、运行本程序，以及各界面元素的功能。

---

## 1. 运行环境

| 用途 | 需要的东西 |
| --- | --- |
| 命令行工具 / 自动化测试 | 任意支持 C++17 的编译器（本工程用 MinGW-w64 g++ 验证） |
| Qt 6 图形界面 | Qt 6（含配套 MinGW 套件）+ CMake |

本工程实际验证过的环境：

```
操作系统   Windows 11 x64
编译器 A   g++ (GCC) 12.2.0   —— D:\w64devkit（构建 核心库 / CLI / 自测）
编译器 B   g++ (GCC) 13.1.0   —— C:\Qt\Tools\mingw1310_64（构建 Qt 图形界面）
图形界面   Qt 6.12.0 (mingw_64)
构建工具   CMake 3.30.5 + Ninja
编辑器     Visual Studio Code / Qt Creator
```

两套编译器都被用来构建并运行了同一份核心算法库，输出逐字节一致 —— 这本身就是作业第 2 关「异构平台结果一致」的一次实证，详见测试报告第 2 节。

---

## 2. 构建

### 2.1 只用 g++（不需要 Qt）

这是最快的方式，能跑通全部算法逻辑与命令行界面。

```powershell
cd D:\S-DES
powershell -ExecutionPolicy Bypass -File scripts\build-cli.ps1
```

产物：

```
build\sdes-cli.exe     命令行工具
build\test-sdes.exe    自动化验收测试
```

如果 `g++` 不在默认位置，可以显式指定：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-cli.ps1 -Compiler "C:\msys64\mingw64\bin\g++.exe"
```

构建 Debug 版本（带调试符号，便于用 gdb 跟踪）：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-cli.ps1 -Configuration Debug
```

### 2.2 安装 Qt 6

1. 运行 Qt 在线安装器（本机已下载在 `D:\qt-online-installer-windows-x64-4.9.0.exe`，也可从 <https://www.qt.io/download-qt-installer> 获取）。

2. 用免费 Qt 账号登录。

3. 选择 **自定义安装（Custom installation）**，勾选以下组件：

   | 组件路径 | 说明 |
   | --- | --- |
   | `Qt` → `Qt 6.x.x` → `MinGW 13.1.0 64-bit` | **必选**，Qt 库本体（名称里的 MinGW 版本随 Qt 版本变化） |
   | `Build Tools` → `MinGW 13.1.0 64-bit` | **必选**，编译器。这就是 `g++.exe` 所在 |
   | `Build Tools` → `CMake` | 可选，`build-gui.ps1` 能自动找到它 |
   | `Build Tools` → `Ninja` | 可选，能让编译更快 |
   | `Build Tools` → `Qt Creator` | 可选，用 IDE 一键构建时更方便 |

   > ⚠ **两个容易踩的点**
   >
   > **分类名会随安装器版本变化。** 老版本安装器里编译器分类叫 `Developer and Designer Tools`，新版本改成了 **`Build Tools`**。如果两个名字都找不到，就在安装器右上角的搜索框里搜 `MinGW`，或往下滚动查看所有顶层分类。
   >
   > **新版安装器不再自动勾选编译器。** 旧版安装器里 MinGW 工具链是 Qt 库的强制依赖，会自动勾上；新版取消了这一行为，必须**手动勾选 `Build Tools → MinGW 13.1.0 64-bit`**，否则装完只有 Qt 库、没有 `g++.exe`，Qt Creator 会报 "No compiler set in kit"。

4. 安装目录保持默认的 `C:\Qt` 即可。**路径中不要有中文或空格**。

5. 装完后可以用这条命令确认编译器是否到位：

   ```powershell
   Test-Path 'C:\Qt\Tools\mingw1310_64\bin\g++.exe'
   ```

   返回 `True` 才算装全。

> **Qt 版本与 MinGW 版本必须配对。** Qt 官方为每个 Qt 版本只提供一两种构建，例如 Qt 6.11 在 Windows x86_64 上只支持 MSVC 2022 或 Mingw-w64 13.1。Qt 库和编译器必须来自同一套，版本号也必须对得上。

> **为什么必须用 Qt 自带的 MinGW？**
> 编译好的 Qt 库依赖特定版本的 `libstdc++`。w64devkit 的 g++ 12.2 与 Qt 自带的 MinGW 13.1 属于不同 ABI 版本，混用会在链接或运行时出现难以排查的错误。用 Qt Creator 时它会自动配对，无需操心。

### 2.3 用 CMake 构建图形界面

```powershell
cd D:\S-DES
powershell -ExecutionPolicy Bypass -File scripts\build-gui.ps1
```

脚本会自动寻找 Qt 版本目录、配套的 MinGW 和 CMake。如果你的 Qt 装在别处：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-gui.ps1 -QtRoot "D:\Qt" -QtVersion "6.12.0"
```

产物：`build-gui\sdes-gui.exe`

### 2.4 用 Qt Creator 构建（最省事）

1. Qt Creator → **文件 → 打开文件或项目** → 选择 `D:\S-DES\CMakeLists.txt`
2. 在「配置项目」页面选择 **MinGW 64-bit** 套件
3. 按 `Ctrl+R` 构建并运行

### 2.5 运行时依赖（已自动部署）

`build-gui.ps1` 在构建成功后会**自动把运行时 DLL 拷进 `build-gui\` 目录**，所以产物可以直接双击运行，也能整目录拷给同学或助教：

1. 拷贝 MinGW 运行时 DLL（`libstdc++-6.dll`、`libgcc_s_seh-1.dll`、`libwinpthread-1.dll`）。这三个是**所有**用该工具链编译出的 exe 都需要的，包括不用 Qt 的 `sdes-cli.exe` 和 `test-sdes.exe`；
2. 对 `sdes-gui.exe` 运行 `windeployqt`，拷入 Qt6Core / Qt6Gui / Qt6Widgets 以及 `platforms` 等插件。

若加了 `-SkipDeploy` 跳过部署，运行前需要手动把 Qt 的 `bin` 目录加进 PATH：

```powershell
$env:PATH = "C:\Qt\6.12.0\mingw_64\bin;$env:PATH"
```

> ⚠ **不部署会怎样？** 直接双击会以退出码 `0xC0000135`（`STATUS_DLL_NOT_FOUND`）**静默失败** —— 窗口一闪而过，连错误提示都没有。这是 Windows 上 MinGW 程序最常见的坑，脚本已经替你处理掉了。

---

## 3. 图形界面使用说明

主窗口用五个标签页对应作业的五个关卡。窗口底部的状态栏会显示当前使用的密钥扩展读法。

### 3.1 标签页「1. 基本加解密」—— 第 1 关

| 控件 | 说明 |
| --- | --- |
| 密钥 K | 10 bit 密钥，只接受 0/1，输入框自带校验 |
| 明文 P / 密文 C | 8 bit 分组，只接受 0/1 |
| 加密 P → C | 加密，结果填入「输出」栏 |
| 解密 C → P | 解密，结果填入「输出」栏 |
| 把结果填回输入 | 把输出栏的内容搬到输入栏，方便连续做「加密 → 再解密」验证 |
| 输出 / 状态 | 本次运算的结果与一句摘要 |
| 下方大文本框 | **完整的中间过程**：密钥扩展的每一步、两轮 Feistel 的 L/R/轮密钥/f 输出、IP 与 IP⁻¹ 的结果 |

这项「展开中间过程」是特意做的：S-DES 每一步都是位运算，只看到最终密文无法判断哪一步出错，把中间结果摊开就能和手算、和同学逐步比对。

### 3.2 标签页「2. 交叉测试」—— 第 2 关

以表格形式列出 8 组标准测试向量（密钥、明文、密文、轮密钥）。表格内容由程序**实时计算**，不是写死的字符串。

- **复制为 Markdown 表格** —— 一键复制，方便直接贴进作业报告或发给组员。
- **按当前设置重新计算** —— 切换读法或 S 盒后刷新表格。

交叉测试的做法：A、B 两组约定同一组 `(K, P)`，各自用自己的程序加密，比较密文是否一致；一致则说明两套程序在算法流程和转换单元上是等价的。

### 3.3 标签页「3. 字符串加解密」—— 第 3 关

| 控件 | 说明 |
| --- | --- |
| 密钥 K | 10 bit |
| 输入框 | 加密时填明文文本；解密时填密文的**十六进制串** |
| 加密文本 → 密文 | 逐字节加密，输出十六进制 |
| 解密十六进制 → 文本 | 把十六进制还原成字节后逐字节解密 |
| 把结果填回输入 | 便于做「加密再解密」的往返验证 |

为什么密文用十六进制显示？因为按 1 Byte 分组独立加密后，输出字节是不可打印的乱码，直接显示会破坏界面。程序另外会用 `.` 代替不可打印字节以便直观查看。

### 3.4 标签页「4. 暴力破解」—— 第 4 关

| 控件 | 说明 |
| --- | --- |
| 明密文对输入框 | **每行一对**，格式 `明文:密文`，可填多对 |
| 工作线程数 | `自动`表示按 CPU 核心数决定，也可手动指定 1~64 |
| 开始暴力破解 | 在**后台线程**穷举 1024 个密钥，界面不会卡死 |
| 进度条 | 实时显示已遍历的密钥数 |
| 下方结果框 | 时间戳（开始/结束）、线程数、遍历数量、总耗时（毫秒与微秒）、每秒尝试数、命中的全部候选密钥 |

填多对明密文可以显著缩小候选范围：只填一对时通常有多个密钥都能通过验证，补第二对后往往只剩一两个。

### 3.5 标签页「5. 密钥分析」—— 第 5 关

| 控件 | 说明 |
| --- | --- |
| 明文分组 P | 固定一个 8 bit 明文 |
| 分析该明文的密钥碰撞 | 穷举 1024 个密钥，统计密文分布 |
| 分析整个密钥空间 | 判断是否存在「对任意明文都等价」的密钥对 |
| 中部表格 | 每个密文 → 能产出它的全部密钥（按密钥个数降序） |
| 底部文本框 | 密钥空间的整体结构结论 |

### 3.6 菜单

**设置 → 密钥扩展读法**

- *教材递进式*（默认）
- *公式字面式*

**设置 → S 盒版本**

- *作业指定版本*（默认）
- *Schneier 教材原始版本* —— 选它之后，用 `K=1010000010, P=10010111` 加密应得到 `00111000`，可用来自证实现无误。

切换任意设置后，交叉测试表格会自动刷新。

---

## 4. 命令行使用说明

不带参数运行会进入交互式菜单：

```powershell
.\build\sdes-cli.exe
```

也可以直接用子命令。

### 4.1 `demo` —— 一键演示五关

```powershell
.\build\sdes-cli.exe demo
```

依次输出第 1~5 关的完整过程与结果，适合直接截图放进报告。

### 4.2 `vectors` —— 标准交叉测试向量表

```powershell
.\build\sdes-cli.exe vectors
```

### 4.3 `encrypt` / `decrypt` —— 单个分组

```powershell
.\build\sdes-cli.exe encrypt --key 1010000010 --input 10010111
.\build\sdes-cli.exe decrypt --key 1010000010 --input 00111000
```

### 4.4 `text` —— 字符串加解密

```powershell
# 加密：直接给明文
.\build\sdes-cli.exe text --key 1010000010 --encrypt "Information Security"

# 解密：给密文的十六进制
.\build\sdes-cli.exe text --key 1010000010 --decrypt AF5AD42F3A46BD4EC72F5A624FF860693AC74E30
```

### 4.5 `brute` —— 暴力破解

```powershell
.\build\sdes-cli.exe brute --pair 10010111:11110110
.\build\sdes-cli.exe brute --pair 10010111:11110110 --pair 00001111:00111101 --threads 4
```

### 4.6 `analyse` / `keyspace` —— 第 5 关

```powershell
# 固定一个明文的密文分布
.\build\sdes-cli.exe analyse --plain 10010111

# 整个密钥空间的结构
.\build\sdes-cli.exe keyspace
```

### 4.7 通用选项

| 选项 | 取值 | 默认 |
| --- | --- | --- |
| `--mode` | `textbook`（教材递进式）/ `literal`（公式字面式） | `textbook` |
| `--sbox` | `homework`（作业指定）/ `textbook`（教材原始） | `homework` |

---

## 5. 常见问题

**Q：`.\build\sdes-cli.exe` 提示找不到文件？**
先运行一次 `scripts\build-cli.ps1`。产物在 `build\` 目录下。

**Q：控制台输出的中文是乱码？**
程序已在启动时设置控制台代码页为 UTF-8。如果仍然乱码，在运行前执行 `chcp 65001`，或改用 Windows Terminal。

**Q：`build-gui.ps1` 报找不到 Qt？**
确认已装 Qt 6 的 **MinGW 64-bit** 组件；若装在非默认位置，用 `-QtRoot` 指定，例如 `-QtRoot "D:\Qt"`。

**Q：`build-gui.ps1` 报找不到 CMake？**
打开 Qt 的「维护工具」（Maintenance Tool）→ **添加或移除组件**，在 `Build Tools` 分类下勾上 `CMake` 和 `Ninja`；或单独装 CMake 并加入 PATH。

**Q：安装器里找不到 `MinGW 13.1.0 64-bit`？**
先确认看的是 `Build Tools` 分类（老版本叫 `Developer and Designer Tools`），并确认**手动勾选**了它 —— 新版安装器不会自动勾。如果分类里确实没有，多半是组件列表没加载全：在安装器的 **设置 → 仓库（Repositories）** 里换个镜像重试；也可以直接用命令行绕开界面：

```powershell
# 在安装器所在目录执行，先搜出包名
.\qt-online-installer-windows-x64-4.9.0.exe search --type package --filter-packages DisplayName=MinGW

# 找到后按包名直接装（包名为 qt.tools.win64_mingw1310）
.\qt-online-installer-windows-x64-4.9.0.exe install qt.tools.win64_mingw1310
```

**Q：编译 Qt 版时报一堆 `undefined reference to ...std::__cxx11...`？**
说明混用了编译器。Qt 程序必须用 Qt 自带的那套 MinGW，不能和 w64devkit 的 g++ 混用。

**Q：和同学交叉测试对不上？**
先确认三件事：① 密钥扩展读法是否一致（见 README 的「两种读法」一节）；② S 盒是否都用作业指定版本（`SBox₂` 第 2、3 行）；③ 位序约定是否一致（本工程用「索引 0 = 最左位」，置换表的 1-based 序号直接对应）。

**Q：暴力破解为什么要用多线程，密钥空间不是只有 1024 吗？**
确实，1024 个密钥在单线程下也只要零点几毫秒，多线程反而会付出线程创建开销（实测 24 线程约 0.7 毫秒，单线程约 0.1 毫秒）。这里实现多线程是为了演示**在密钥空间很大时该怎么写**：把密钥空间分块、线程用原子计数器抢块、带进度回调与计时。这一点在测试报告里有实测数据对比。

**Q：用 PowerShell 管道给交互菜单喂多行输入时，选项会错位？**
这是 Windows PowerShell 5.1 向原生程序写 stdin 时的编码行为，不是程序本身的问题（键盘逐行输入、以及交互式使用都正常）。如果需要脚本化驱动菜单，改用文件重定向：

```powershell
$tmp = Join-Path $env:TEMP 'menu-in.txt'
[System.IO.File]::WriteAllText($tmp, "1`n1010000010`n0`n", (New-Object System.Text.UTF8Encoding $false))
cmd /c ".\build\sdes-cli.exe < `"$tmp`""
```

日常使用建议直接用子命令（`encrypt` / `text` / `brute` 等），它们本身就是为非交互调用设计的。
