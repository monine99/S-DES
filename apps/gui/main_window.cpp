// =============================================================================
//  apps/gui/main_window.cpp
//  S-DES 图形界面的实现
// =============================================================================

#include "main_window.hpp"

#include <QAction>
#include <QActionGroup>
#include <QApplication>
#include <QChar>
#include <QClipboard>
#include <QDateTime>
#include <QFontDatabase>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QSpinBox>
#include <QStatusBar>
#include <QStringList>
#include <QTabWidget>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <cctype>
#include <optional>
#include <string>

#include "sdes/analysis.hpp"
#include "sdes/tables.hpp"

namespace {

// -----------------------------------------------------------------------------
//  小工具
// -----------------------------------------------------------------------------

/// 只允许 0/1、长度不超过 maxBits 的输入校验器。
QRegularExpressionValidator* binaryValidator(int maxBits, QObject* parent) {
    const QString pattern = QStringLiteral("[01]{0,%1}").arg(maxBits);
    return new QRegularExpressionValidator(QRegularExpression(pattern), parent);
}

QFont monospaceFont() {
    return QFontDatabase::systemFont(QFontDatabase::FixedFont);
}

QString toHexString(const std::string& data) {
    QString text;
    for (const unsigned char byte : data) {
        text += QString("%1").arg(byte, 2, 16, QLatin1Char('0')).toUpper();
    }
    return text;
}

/// 解析十六进制串（允许空格、冒号、短横线分组）。失败返回 nullopt。
std::optional<std::string> fromHexString(const QString& hexText) {
    std::string cleaned;
    for (const QChar character : hexText) {
        const QChar lower = character.toLower();
        const bool isDecimalDigit =
            (character >= QLatin1Char('0') && character <= QLatin1Char('9'));
        const bool isHexLetter = (lower >= QLatin1Char('a') && lower <= QLatin1Char('f'));

        if (isDecimalDigit || isHexLetter) {
            cleaned.push_back(lower.toLatin1());
        } else if (character.isSpace() || character == QLatin1Char(':') || character == QLatin1Char('-')) {
            continue;  // 允许用空格/冒号/短横线分组，方便阅读
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
        const int value = std::stoi(cleaned.substr(index, 2), nullptr, 16);
        bytes.push_back(static_cast<char>(value));
    }
    return bytes;
}

/// 把不可打印字节替换成 '.'，避免界面里出现乱码控制字符。
QString toDisplayable(const std::string& data) {
    QString text;
    for (const unsigned char byte : data) {
        text += (byte >= 0x20 && byte < 0x7F) ? QChar(byte) : QLatin1Char('.');
    }
    return text;
}

QString describeKeySchedule(const sdes::Cipher& cipher) {
    const sdes::KeyScheduleTrace trace =
        sdes::traceKeySchedule(cipher.masterKey(), cipher.keyScheduleMode());
    const auto halves = trace.afterP10.split();

    QString text;
    text += QString("  密钥 K           = %1\n").arg(QString::fromStdString(trace.masterKey.toString()));
    text += QString("  P10(K)           = %1   (左半 %2 | 右半 %3)\n")
                .arg(QString::fromStdString(trace.afterP10.toString()),
                     QString::fromStdString(halves.first.toString()),
                     QString::fromStdString(halves.second.toString()));
    text += QString("  Shift^1(P10(K))  = %1   -> k1 = %2\n")
                .arg(QString::fromStdString(trace.afterShift1.toString()),
                     QString::fromStdString(trace.k1.toString()));
    text += QString("  Shift^2(P10(K))  = %1   -> k2 = %2\n")
                .arg(QString::fromStdString(trace.afterShift2.toString()),
                     QString::fromStdString(trace.k2.toString()));
    return text;
}

QString describeCipherTrace(const sdes::CipherTrace& trace) {
    QString text;
    text += QString("  IP(输入)         = %1   (左半 %2 | 右半 %3)\n")
                .arg(QString::fromStdString(trace.afterIP.toString()),
                     QString::fromStdString(trace.leftBeforeRound1.toString()),
                     QString::fromStdString(trace.rightBeforeRound1.toString()));
    text += QString("  第 1 轮 密钥     = %1   f_k1 = %2   轮输出 = %3\n")
                .arg(QString::fromStdString(trace.firstRoundKey.toString()),
                     QString::fromStdString(trace.afterFeistel1.toString()),
                     QString::fromStdString(trace.afterRound1.toString()));
    text += QString("  SW 之后          = %1   (左半 %2 | 右半 %3)\n")
                .arg(QString::fromStdString(trace.afterSwap.toString()),
                     QString::fromStdString(trace.leftBeforeRound2.toString()),
                     QString::fromStdString(trace.rightBeforeRound2.toString()));
    text += QString("  第 2 轮 密钥     = %1   f_k2 = %2   轮输出 = %3\n")
                .arg(QString::fromStdString(trace.secondRoundKey.toString()),
                     QString::fromStdString(trace.afterFeistel2.toString()),
                     QString::fromStdString(trace.afterRound2.toString()));
    text += QString("  IP^-1 之后       = %1\n").arg(QString::fromStdString(trace.output.toString()));
    return text;
}

/// 第 2 关使用的标准测试向量（与 CLI 的 vectors 子命令保持一致）。
struct TestVector {
    const char* key;
    const char* plaintext;
};

constexpr TestVector kCrossTestVectors[] = {
    {"1010000010", "10010111"},
    {"0000000000", "00000000"},
    {"1111111111", "11111111"},
    {"1100101010", "10010111"},
    {"1010101010", "01010101"},
    {"0111111110", "11110000"},
    {"1000000001", "00001111"},
    {"0011001100", "10101010"},
};

/// 统一每个标签页的留白，并把该页的主操作按钮标上强调样式。
///
/// 约定：每页的主操作按钮放在最左边，因此取页内第一个 QPushButton。
/// 这样集中处理而不是在每个 new QPushButton 后面各写一行 setProperty，
/// 是为了避免「新加了按钮却忘了标记主次」这类遗漏。
void applyPageChrome(QTabWidget* tabs) {
    if (tabs == nullptr) {
        return;
    }

    for (int index = 0; index < tabs->count(); ++index) {
        QWidget* page = tabs->widget(index);
        if (page == nullptr) {
            continue;
        }

        // 页面留白：Qt 默认值（边距约 9px、间距 6px）偏紧，放开后卡片之间才有呼吸感
        if (auto* pageLayout = qobject_cast<QVBoxLayout*>(page->layout())) {
            pageLayout->setContentsMargins(20, 18, 20, 18);
            pageLayout->setSpacing(14);
        }

        // 页内第一个按钮 = 该页的主操作，套用强调色
        if (auto* primaryButton = page->findChild<QPushButton*>()) {
            primaryButton->setProperty("primary", true);
        }
    }
}

}  // namespace

// =============================================================================
//  BruteForceTask
// =============================================================================

BruteForceTask::BruteForceTask(std::vector<sdes::KnownPair> pairs, sdes::BruteForceOptions options,
                               QObject* parent)
    : QThread(parent), pairs_(std::move(pairs)), options_(std::move(options)) {}

void BruteForceTask::run() {
    sdes::BruteForceOptions options = options_;
    // 进度回调发生在工作线程里；emit 跨线程会自动排队投递到主线程，是线程安全的。
    options.onProgress = [this](std::size_t tested, std::size_t total) {
        emit progressChanged(static_cast<int>(tested), static_cast<int>(total));
    };
    result_ = sdes::bruteForceKey(pairs_, options);
}

// =============================================================================
//  MainWindow
// =============================================================================

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle(tr("S-DES 加解密程序 —— 信息安全导论 第 5 次课作业"));

    auto* tabs = new QTabWidget(this);
    tabs->addTab(createBasicTab(), tr("1. 基本加解密"));
    tabs->addTab(createCrossTestTab(), tr("2. 交叉测试"));
    tabs->addTab(createTextTab(), tr("3. 字符串加解密"));
    tabs->addTab(createBruteForceTab(), tr("4. 暴力破解"));
    tabs->addTab(createAnalysisTab(), tr("5. 密钥分析"));
    setCentralWidget(tabs);
    applyPageChrome(tabs);

    createMenus();
    statusBar()->showMessage(tr("就绪 —— 密钥扩展读法：%1")
                                 .arg(QString::fromUtf8(sdes::describeKeyScheduleMode(m_keyScheduleMode))));
    resize(1180, 820);
}

// -----------------------------------------------------------------------------
//  读法与加密器
// -----------------------------------------------------------------------------

sdes::Cipher MainWindow::makeCipher(const sdes::Block10& key) const {
    return sdes::Cipher(key, m_sBoxes, m_keyScheduleMode);
}

bool MainWindow::readKeyFrom(QLineEdit* field, sdes::Block10& keyOut) {
    const std::optional<sdes::Block10> parsed = sdes::Block10::tryFromString(field->text().toStdString());
    if (!parsed.has_value()) {
        reportError(tr("密钥必须是长度不超过 10 的 0/1 串，当前输入是「%1」。").arg(field->text()));
        return false;
    }
    keyOut = *parsed;
    return true;
}

bool MainWindow::readBlockFrom(QLineEdit* field, sdes::Block8& blockOut) {
    const std::optional<sdes::Block8> parsed = sdes::Block8::tryFromString(field->text().toStdString());
    if (!parsed.has_value()) {
        reportError(tr("数据分组必须是长度不超过 8 的 0/1 串，当前输入是「%1」。").arg(field->text()));
        return false;
    }
    blockOut = *parsed;
    return true;
}

void MainWindow::reportError(const QString& message) {
    QMessageBox::warning(this, tr("输入有误"), message);
}

// -----------------------------------------------------------------------------
//  第 1 关：基本加解密
// -----------------------------------------------------------------------------

QWidget* MainWindow::createBasicTab() {
    auto* tab = new QWidget;
    auto* layout = new QVBoxLayout(tab);

    auto* inputGroup = new QGroupBox(tr("输入（分组 8 bit，密钥 10 bit）"), tab);
    auto* form = new QFormLayout(inputGroup);

    m_keyInput = new QLineEdit(QStringLiteral("1010000010"), inputGroup);
    m_keyInput->setValidator(binaryValidator(10, m_keyInput));
    m_keyInput->setMaxLength(10);
    m_keyInput->setFont(monospaceFont());
    form->addRow(tr("密钥 K"), m_keyInput);

    m_plainInput = new QLineEdit(QStringLiteral("10010111"), inputGroup);
    m_plainInput->setValidator(binaryValidator(8, m_plainInput));
    m_plainInput->setMaxLength(8);
    m_plainInput->setFont(monospaceFont());
    form->addRow(tr("明文 P / 密文 C"), m_plainInput);

    layout->addWidget(inputGroup);

    auto* buttonRow = new QHBoxLayout;
    auto* encryptButton = new QPushButton(tr("加密  P → C"), tab);
    auto* decryptButton = new QPushButton(tr("解密  C → P"), tab);
    auto* swapButton = new QPushButton(tr("把结果填回输入"), tab);
    buttonRow->addWidget(encryptButton);
    buttonRow->addWidget(decryptButton);
    buttonRow->addWidget(swapButton);
    buttonRow->addStretch();
    layout->addLayout(buttonRow);

    auto* outputGroup = new QGroupBox(tr("结果"), tab);
    auto* outputForm = new QFormLayout(outputGroup);
    m_cipherOutput = new QLineEdit(outputGroup);
    m_cipherOutput->setReadOnly(true);
    m_cipherOutput->setFont(monospaceFont());
    outputForm->addRow(tr("输出"), m_cipherOutput);
    m_basicStatus = new QLabel(tr("尚未执行加解密。"), outputGroup);
    outputForm->addRow(tr("状态"), m_basicStatus);
    layout->addWidget(outputGroup);

    m_basicTrace = new QPlainTextEdit(tab);
    m_basicTrace->setReadOnly(true);
    m_basicTrace->setFont(monospaceFont());
    m_basicTrace->setPlaceholderText(tr("点击「加密」或「解密」后，这里会逐步显示密钥扩展与两轮 Feistel 的中间结果。"));
    layout->addWidget(m_basicTrace, 1);

    connect(encryptButton, &QPushButton::clicked, this, &MainWindow::onBlockEncryptClicked);
    connect(decryptButton, &QPushButton::clicked, this, &MainWindow::onBlockDecryptClicked);
    connect(swapButton, &QPushButton::clicked, this, &MainWindow::onBlockSwapClicked);
    return tab;
}

void MainWindow::onBlockEncryptClicked() {
    sdes::Block10 key;
    sdes::Block8 plaintext;
    if (!readKeyFrom(m_keyInput, key) || !readBlockFrom(m_plainInput, plaintext)) {
        return;
    }

    const sdes::Cipher cipher = makeCipher(key);
    const sdes::CipherTrace trace = cipher.traceEncrypt(plaintext);

    m_cipherOutput->setText(QString::fromStdString(trace.output.toString()));
    m_basicStatus->setText(tr("加密完成：明文 %1 → 密文 %2")
                               .arg(QString::fromStdString(plaintext.toString()),
                                    QString::fromStdString(trace.output.toString())));

    QString text = tr("【密钥扩展】\n");
    text += describeKeySchedule(cipher);
    text += tr("\n【加密过程】\n");
    text += describeCipherTrace(trace);
    m_basicTrace->setPlainText(text);
}

void MainWindow::onBlockDecryptClicked() {
    sdes::Block10 key;
    sdes::Block8 ciphertext;
    if (!readKeyFrom(m_keyInput, key) || !readBlockFrom(m_plainInput, ciphertext)) {
        return;
    }

    const sdes::Cipher cipher = makeCipher(key);
    const sdes::CipherTrace trace = cipher.traceDecrypt(ciphertext);

    m_cipherOutput->setText(QString::fromStdString(trace.output.toString()));
    m_basicStatus->setText(tr("解密完成：密文 %1 → 明文 %2")
                               .arg(QString::fromStdString(ciphertext.toString()),
                                    QString::fromStdString(trace.output.toString())));

    QString text = tr("【密钥扩展】\n");
    text += describeKeySchedule(cipher);
    text += tr("\n【解密过程（轮密钥顺序与加密相反）】\n");
    text += describeCipherTrace(trace);
    m_basicTrace->setPlainText(text);
}

void MainWindow::onBlockSwapClicked() {
    if (!m_cipherOutput->text().isEmpty()) {
        m_plainInput->setText(m_cipherOutput->text());
        m_cipherOutput->clear();
    }
}

// -----------------------------------------------------------------------------
//  第 2 关：交叉测试
// -----------------------------------------------------------------------------

QWidget* MainWindow::createCrossTestTab() {
    auto* tab = new QWidget;
    auto* layout = new QVBoxLayout(tab);

    auto* hint = new QLabel(
        tr("下表由本程序按标准流程实时算出。B 组同学用自己写的程序加密同一组 (K, P)，"
           "若得到的 C 与表中完全一致，即通过交叉测试。"),
        tab);
    hint->setWordWrap(true);
    layout->addWidget(hint);

    m_vectorTable = new QTableWidget(0, 5, tab);
    m_vectorTable->setHorizontalHeaderLabels(
        {tr("序号"), tr("密钥 K (10 bit)"), tr("明文 P"), tr("密文 C"), tr("轮密钥 k1 / k2")});
    // 前几列按内容自适应，最后一列（轮密钥）吃掉剩余宽度。
    // 比五列平均分配紧凑得多 —— 二进制串本身宽度固定，均分会留出大片空白。
    m_vectorTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_vectorTable->horizontalHeader()->setStretchLastSection(true);
    m_vectorTable->verticalHeader()->setVisible(false);
    m_vectorTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_vectorTable->setAlternatingRowColors(true);
    m_vectorTable->setFont(monospaceFont());
    layout->addWidget(m_vectorTable, 1);

    auto* buttonRow = new QHBoxLayout;
    auto* copyButton = new QPushButton(tr("复制为 Markdown 表格"), tab);
    auto* reloadButton = new QPushButton(tr("按当前设置重新计算"), tab);
    buttonRow->addWidget(copyButton);
    buttonRow->addWidget(reloadButton);
    buttonRow->addStretch();
    layout->addLayout(buttonRow);

    connect(copyButton, &QPushButton::clicked, this, &MainWindow::onCopyVectorsClicked);
    connect(reloadButton, &QPushButton::clicked, this, &MainWindow::refreshVectorTable);

    refreshVectorTable();
    return tab;
}

void MainWindow::refreshVectorTable() {
    if (m_vectorTable == nullptr) {
        return;
    }

    const std::size_t vectorCount = sizeof(kCrossTestVectors) / sizeof(kCrossTestVectors[0]);
    m_vectorTable->setUpdatesEnabled(false);
    m_vectorTable->setRowCount(static_cast<int>(vectorCount));

    for (std::size_t index = 0; index < vectorCount; ++index) {
        const TestVector& vector = kCrossTestVectors[index];
        const sdes::Block10 key = sdes::Block10::fromString(vector.key);
        const sdes::Block8 plaintext = sdes::Block8::fromString(vector.plaintext);
        const sdes::Cipher cipher = makeCipher(key);
        const sdes::Block8 ciphertext = cipher.encrypt(plaintext);

        const sdes::RoundKeys roundKeys = sdes::deriveRoundKeys(key, m_keyScheduleMode);
        const QString roundKeyText = QString("%1 / %2")
                                         .arg(QString::fromStdString(roundKeys.k1.toString()),
                                              QString::fromStdString(roundKeys.k2.toString()));

        const QStringList cells{
            QString::number(index + 1),
            QString::fromStdString(key.toString()),
            QString::fromStdString(plaintext.toString()),
            QString::fromStdString(ciphertext.toString()),
            roundKeyText,
        };
        for (int column = 0; column < cells.size(); ++column) {
            auto* item = new QTableWidgetItem(cells.at(column));
            item->setTextAlignment(Qt::AlignCenter);
            m_vectorTable->setItem(static_cast<int>(index), column, item);
        }
    }

    m_vectorTable->setUpdatesEnabled(true);
}

void MainWindow::onCopyVectorsClicked() {
    QString markdown;
    markdown += "| 序号 | 密钥 K (10 bit) | 明文 P | 密文 C | k1 | k2 |\n";
    markdown += "| --- | --- | --- | --- | --- | --- |\n";

    const std::size_t vectorCount = sizeof(kCrossTestVectors) / sizeof(kCrossTestVectors[0]);
    for (std::size_t index = 0; index < vectorCount; ++index) {
        const TestVector& vector = kCrossTestVectors[index];
        const sdes::Block10 key = sdes::Block10::fromString(vector.key);
        const sdes::Block8 plaintext = sdes::Block8::fromString(vector.plaintext);
        const sdes::Cipher cipher = makeCipher(key);
        const sdes::RoundKeys roundKeys = sdes::deriveRoundKeys(key, m_keyScheduleMode);

        markdown += QString("| %1 | %2 | %3 | %4 | %5 | %6 |\n")
                        .arg(index + 1)
                        .arg(QString::fromStdString(key.toString()))
                        .arg(QString::fromStdString(plaintext.toString()))
                        .arg(QString::fromStdString(cipher.encrypt(plaintext).toString()))
                        .arg(QString::fromStdString(roundKeys.k1.toString()))
                        .arg(QString::fromStdString(roundKeys.k2.toString()));
    }

    QApplication::clipboard()->setText(markdown);
    statusBar()->showMessage(tr("已把测试向量表复制到剪贴板（Markdown 格式）。"), 5000);
}

// -----------------------------------------------------------------------------
//  第 3 关：字符串加解密
// -----------------------------------------------------------------------------

QWidget* MainWindow::createTextTab() {
    auto* tab = new QWidget;
    auto* layout = new QVBoxLayout(tab);

    auto* keyRow = new QHBoxLayout;
    keyRow->addWidget(new QLabel(tr("密钥 K（10 bit）："), tab));
    m_textKey = new QLineEdit(QStringLiteral("1010000010"), tab);
    m_textKey->setValidator(binaryValidator(10, m_textKey));
    m_textKey->setMaxLength(10);
    m_textKey->setFont(monospaceFont());
    keyRow->addWidget(m_textKey, 1);
    layout->addLayout(keyRow);

    layout->addWidget(new QLabel(tr("输入（加密时填明文文本；解密时填密文的十六进制串）："), tab));
    m_textInput = new QPlainTextEdit(tab);
    m_textInput->setPlaceholderText(tr("例如：Information Security"));
    layout->addWidget(m_textInput, 1);

    auto* buttonRow = new QHBoxLayout;
    auto* encryptButton = new QPushButton(tr("加密文本 → 密文"), tab);
    auto* decryptButton = new QPushButton(tr("解密十六进制 → 文本"), tab);
    auto* swapButton = new QPushButton(tr("把结果填回输入"), tab);
    buttonRow->addWidget(encryptButton);
    buttonRow->addWidget(decryptButton);
    buttonRow->addWidget(swapButton);
    buttonRow->addStretch();
    layout->addLayout(buttonRow);

    layout->addWidget(new QLabel(tr("输出："), tab));
    m_textOutput = new QPlainTextEdit(tab);
    m_textOutput->setReadOnly(true);
    layout->addWidget(m_textOutput, 1);

    m_textStatus = new QLabel(tr("提示：密文按 1 Byte 一组独立加密，长度与明文相同，内容多为乱码，"
                                 "所以用十六进制显示。"),
                              tab);
    m_textStatus->setWordWrap(true);
    layout->addWidget(m_textStatus);

    connect(encryptButton, &QPushButton::clicked, this, &MainWindow::onTextEncryptClicked);
    connect(decryptButton, &QPushButton::clicked, this, &MainWindow::onTextDecryptClicked);
    connect(swapButton, &QPushButton::clicked, this, &MainWindow::onTextSwapClicked);
    return tab;
}

void MainWindow::onTextEncryptClicked() {
    sdes::Block10 key;
    if (!readKeyFrom(m_textKey, key)) {
        return;
    }

    const std::string plaintext = m_textInput->toPlainText().toStdString();
    if (plaintext.empty()) {
        m_textStatus->setText(tr("请输入要加密的文本。"));
        return;
    }

    const sdes::Cipher cipher = makeCipher(key);
    const std::string ciphertext = cipher.encryptText(plaintext);

    m_textOutput->setPlainText(toHexString(ciphertext));
    m_textStatus->setText(tr("加密完成：明文 %1 字节（%2）→ 密文 %3 字节（%4）")
                              .arg(plaintext.size())
                              .arg(QString::fromUtf8(plaintext.c_str()))
                              .arg(ciphertext.size())
                              .arg(toDisplayable(ciphertext)));
}

void MainWindow::onTextDecryptClicked() {
    sdes::Block10 key;
    if (!readKeyFrom(m_textKey, key)) {
        return;
    }

    const std::optional<std::string> ciphertext = fromHexString(m_textInput->toPlainText());
    if (!ciphertext.has_value()) {
        reportError(tr("解密时输入必须是偶数长度的十六进制串（可包含空格分隔）。"));
        return;
    }
    if (ciphertext->empty()) {
        m_textStatus->setText(tr("请输入要解密的密文。"));
        return;
    }

    const sdes::Cipher cipher = makeCipher(key);
    const std::string plaintext = cipher.decryptText(*ciphertext);

    m_textOutput->setPlainText(QString::fromUtf8(plaintext.c_str(), static_cast<int>(plaintext.size())));
    m_textStatus->setText(tr("解密完成：密文 %1 字节 → 明文 %2 字节").arg(ciphertext->size()).arg(plaintext.size()));
}

void MainWindow::onTextSwapClicked() {
    const QString output = m_textOutput->toPlainText();
    if (!output.isEmpty()) {
        m_textInput->setPlainText(output);
        m_textOutput->clear();
    }
}

// -----------------------------------------------------------------------------
//  第 4 关：暴力破解
// -----------------------------------------------------------------------------

QWidget* MainWindow::createBruteForceTab() {
    auto* tab = new QWidget;
    auto* layout = new QVBoxLayout(tab);

    auto* hint = new QLabel(
        tr("每行填一对已知的明密文，格式为 明文:密文（例如 10010111:00111000）。"
           "程序会穷举全部 1024 个密钥，找出所有能把每对明文都加密成对应密文的密钥。"),
        tab);
    hint->setWordWrap(true);
    layout->addWidget(hint);

    m_brutePairs = new QPlainTextEdit(tab);
    m_brutePairs->setPlainText(QStringLiteral("10010111:00111000"));
    m_brutePairs->setFont(monospaceFont());
    m_brutePairs->setMaximumHeight(110);
    layout->addWidget(m_brutePairs);

    auto* controlRow = new QHBoxLayout;
    controlRow->addWidget(new QLabel(tr("工作线程数："), tab));
    m_bruteThreads = new QSpinBox(tab);
    m_bruteThreads->setRange(0, 64);
    m_bruteThreads->setValue(0);
    m_bruteThreads->setSpecialValueText(tr("自动"));
    m_bruteThreads->setToolTip(tr("0 表示按 CPU 核心数自动决定"));
    controlRow->addWidget(m_bruteThreads);

    m_bruteButton = new QPushButton(tr("开始暴力破解"), tab);
    controlRow->addWidget(m_bruteButton);
    controlRow->addStretch();
    layout->addLayout(controlRow);

    m_bruteProgress = new QProgressBar(tab);
    m_bruteProgress->setRange(0, static_cast<int>(sdes::kKeySpaceSize));
    m_bruteProgress->setValue(0);
    m_bruteProgress->setFormat(tr("已遍历 %v / %m 个密钥"));
    layout->addWidget(m_bruteProgress);

    m_bruteLog = new QPlainTextEdit(tab);
    m_bruteLog->setReadOnly(true);
    m_bruteLog->setFont(monospaceFont());
    layout->addWidget(m_bruteLog, 1);

    connect(m_bruteButton, &QPushButton::clicked, this, &MainWindow::onBruteForceClicked);
    return tab;
}

void MainWindow::onBruteForceClicked() {
    if (m_bruteTask != nullptr && m_bruteTask->isRunning()) {
        return;
    }

    // 解析每一行的 明文:密文
    std::vector<sdes::KnownPair> pairs;
    const QStringList lines = m_brutePairs->toPlainText().split(QRegularExpression("[\\r\\n]+"),
                                                                Qt::SkipEmptyParts);
    for (const QString& line : lines) {
        const int separator = line.indexOf(QLatin1Char(':'));
        if (separator < 0) {
            reportError(tr("这一行格式不对：「%1」。应为 明文:密文").arg(line.trimmed()));
            return;
        }
        const std::optional<sdes::Block8> plaintext =
            sdes::Block8::tryFromString(line.left(separator).trimmed().toStdString());
        const std::optional<sdes::Block8> ciphertext =
            sdes::Block8::tryFromString(line.mid(separator + 1).trimmed().toStdString());
        if (!plaintext.has_value() || !ciphertext.has_value()) {
            reportError(tr("这一行里的分组不是合法的 8 bit 0/1 串：「%1」").arg(line.trimmed()));
            return;
        }
        pairs.push_back(sdes::KnownPair{*plaintext, *ciphertext});
    }

    if (pairs.empty()) {
        reportError(tr("请至少填写一对已知的明密文。"));
        return;
    }

    sdes::BruteForceOptions options;
    options.workerThreads = static_cast<unsigned>(m_bruteThreads->value());
    options.keyScheduleMode = m_keyScheduleMode;

    m_bruteButton->setEnabled(false);
    m_bruteProgress->setValue(0);
    m_bruteLog->clear();
    m_bruteLog->appendPlainText(tr("已提交明密文对 %1 组，开始穷举密钥空间（1024）…").arg(pairs.size()));

    m_bruteTask = new BruteForceTask(std::move(pairs), options, this);
    connect(m_bruteTask, &BruteForceTask::progressChanged, this, &MainWindow::onBruteProgress);
    connect(m_bruteTask, &QThread::finished, this, &MainWindow::onBruteFinished);
    m_bruteTask->start();
}

void MainWindow::onBruteProgress(int tested, int total) {
    m_bruteProgress->setRange(0, total);
    m_bruteProgress->setValue(tested);
}

void MainWindow::onBruteFinished() {
    BruteForceTask* task = m_bruteTask;
    m_bruteTask = nullptr;

    if (task == nullptr) {
        return;
    }

    const sdes::BruteForceResult& result = task->result();

    QString text;
    text += tr("时间戳 开始     = %1\n")
                .arg(QDateTime::fromMSecsSinceEpoch(
                         std::chrono::duration_cast<std::chrono::milliseconds>(
                             result.stats.startedAt.time_since_epoch())
                             .count())
                         .toString("yyyy-MM-dd HH:mm:ss.zzz"));
    text += tr("时间戳 结束     = %1\n")
                .arg(QDateTime::fromMSecsSinceEpoch(
                         std::chrono::duration_cast<std::chrono::milliseconds>(
                             result.stats.finishedAt.time_since_epoch())
                             .count())
                         .toString("yyyy-MM-dd HH:mm:ss.zzz"));
    text += tr("工作线程数      = %1\n").arg(result.stats.workerThreads);
    text += tr("遍历密钥数      = %1 / %2\n")
                .arg(result.stats.keysTested)
                .arg(result.stats.keySpaceSize);
    text += tr("总耗时          = %1 毫秒（%2 微秒）\n")
                .arg(QString::number(result.stats.elapsedMilliseconds(), 'f', 3))
                .arg(QString::number(result.stats.elapsedMicroseconds(), 'f', 0));
    text += tr("破解速度        = %1 个密钥/秒\n")
                .arg(QString::number(result.stats.keysPerSecond(), 'f', 0));
    text += tr("命中候选密钥    = %1 个\n").arg(result.candidateKeys.size());
    text += QStringLiteral("\n");

    for (const sdes::Block10& key : result.candidateKeys) {
        text += QString("    %1\n").arg(QString::fromStdString(key.toString()));
    }

    if (result.candidateKeys.size() > 1) {
        text += tr("\n说明：只凭这一组明密文无法唯一确定密钥，上面 %1 个密钥都能通过验证，"
                   "这正是第 5 关要分析的现象。再补一组明密文即可继续缩小范围。")
                    .arg(result.candidateKeys.size());
    }

    m_bruteLog->setPlainText(text);
    m_bruteProgress->setValue(m_bruteProgress->maximum());
    m_bruteButton->setEnabled(true);

    task->deleteLater();
}

// -----------------------------------------------------------------------------
//  第 5 关：密钥分析
// -----------------------------------------------------------------------------

QWidget* MainWindow::createAnalysisTab() {
    auto* tab = new QWidget;
    auto* layout = new QVBoxLayout(tab);

    auto* hint = new QLabel(
        tr("固定一个明文分组，穷举全部 1024 个密钥，统计有多少个不同的密文、"
           "哪些密文会对应对个密钥，以及整个密钥空间里是否存在「等价密钥」。"),
        tab);
    hint->setWordWrap(true);
    layout->addWidget(hint);

    auto* controlRow = new QHBoxLayout;
    controlRow->addWidget(new QLabel(tr("明文分组 P（8 bit）："), tab));
    m_analysisPlain = new QLineEdit(QStringLiteral("10010111"), tab);
    m_analysisPlain->setValidator(binaryValidator(8, m_analysisPlain));
    m_analysisPlain->setMaxLength(8);
    m_analysisPlain->setFont(monospaceFont());
    // QLineEdit 默认的水平尺寸策略是 Expanding，不限制的话会把整行撑开
    m_analysisPlain->setMaximumWidth(200);
    controlRow->addWidget(m_analysisPlain);

    auto* analyseButton = new QPushButton(tr("分析该明文的密钥碰撞"), tab);
    auto* keySpaceButton = new QPushButton(tr("分析整个密钥空间"), tab);
    controlRow->addWidget(analyseButton);
    controlRow->addWidget(keySpaceButton);
    controlRow->addStretch();
    layout->addLayout(controlRow);

    m_analysisSummary = new QPlainTextEdit(tab);
    m_analysisSummary->setReadOnly(true);
    m_analysisSummary->setFont(monospaceFont());
    m_analysisSummary->setMaximumHeight(190);
    layout->addWidget(m_analysisSummary);

    auto* tableLabel = new QLabel(tr("密文 → 能产出它的密钥（按密钥个数从多到少排列）："), tab);
    layout->addWidget(tableLabel);

    m_analysisTable = new QTableWidget(0, 3, tab);
    m_analysisTable->setHorizontalHeaderLabels({tr("密文 C"), tr("密钥个数"), tr("全部密钥")});
    m_analysisTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_analysisTable->verticalHeader()->setVisible(false);
    m_analysisTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_analysisTable->setAlternatingRowColors(true);
    m_analysisTable->setFont(monospaceFont());
    layout->addWidget(m_analysisTable, 2);

    layout->addWidget(new QLabel(tr("密钥空间整体结构："), tab));
    m_keySpaceSummary = new QPlainTextEdit(tab);
    m_keySpaceSummary->setReadOnly(true);
    m_keySpaceSummary->setFont(monospaceFont());
    m_keySpaceSummary->setMaximumHeight(170);
    layout->addWidget(m_keySpaceSummary, 1);

    connect(analyseButton, &QPushButton::clicked, this, &MainWindow::onAnalyseClicked);
    connect(keySpaceButton, &QPushButton::clicked, this, &MainWindow::onKeySpaceClicked);
    return tab;
}

void MainWindow::onAnalyseClicked() {
    sdes::Block8 plaintext;
    if (!readBlockFrom(m_analysisPlain, plaintext)) {
        return;
    }

    const sdes::PlaintextAnalysis analysis = sdes::analysePlaintext(plaintext, m_keyScheduleMode);

    QString summary;
    summary += tr("固定明文 P = %1，穷举全部 %2 个密钥：\n\n")
                   .arg(QString::fromStdString(plaintext.toString()))
                   .arg(analysis.keyCount);
    summary += tr("  不同密文个数             = %1 / 256\n").arg(analysis.distinctCiphertexts);
    summary += tr("  只对应 1 个密钥的密文    = %1\n").arg(analysis.singleKeyCiphertexts);
    summary += tr("  对应 >=2 个密钥的密文    = %1\n").arg(analysis.collidingCiphertexts);
    summary += tr("  落在碰撞里的密钥数       = %1 / %2\n")
                   .arg(analysis.keysInCollisions)
                   .arg(analysis.keyCount);
    summary += tr("  单个密文最多对应密钥数   = %1\n").arg(analysis.maxKeysPerCiphertext);
    summary += tr("  平均每个密文对应密钥数   = %1\n")
                   .arg(QString::number(analysis.averageKeysPerCiphertext, 'f', 3));
    summary += tr("  最拥挤的密文             = %1\n")
                   .arg(QString::fromStdString(analysis.mostCommonCiphertext.toString()));
    summary += tr("  分析耗时                 = %1 毫秒\n")
                   .arg(QString::number(analysis.elapsedMs, 'f', 2));
    summary += tr("\n结论：明文空间只有 256 种、密钥却有 1024 个，由鸽巢原理，"
                  "「不同密钥加密同一明文得到相同密文」必然会发生。");
    m_analysisSummary->setPlainText(summary);

    // 填表：按密钥个数降序
    const sdes::CiphertextKeyMap mapping = sdes::groupKeysByCiphertext(plaintext, m_keyScheduleMode);
    std::vector<std::pair<sdes::Block8, std::vector<sdes::Block10>>> rows(mapping.begin(), mapping.end());
    std::sort(rows.begin(), rows.end(),
              [](const auto& left, const auto& right) { return left.second.size() > right.second.size(); });

    m_analysisTable->setUpdatesEnabled(false);
    m_analysisTable->setRowCount(static_cast<int>(rows.size()));
    for (std::size_t row = 0; row < rows.size(); ++row) {
        QString keysText;
        for (const sdes::Block10& key : rows[row].second) {
            if (!keysText.isEmpty()) {
                keysText += QStringLiteral("  ");
            }
            keysText += QString::fromStdString(key.toString());
        }

        const QStringList cells{
            QString::fromStdString(rows[row].first.toString()),
            QString::number(rows[row].second.size()),
            keysText,
        };
        for (int column = 0; column < cells.size(); ++column) {
            auto* item = new QTableWidgetItem(cells.at(column));
            if (column < 2) {
                item->setTextAlignment(Qt::AlignCenter);
            }
            m_analysisTable->setItem(static_cast<int>(row), column, item);
        }
    }
    m_analysisTable->setUpdatesEnabled(true);
}

void MainWindow::onKeySpaceClicked() {
    std::vector<sdes::EquivalentKeyClass> classes;
    const sdes::KeySpaceAnalysis space = sdes::analyseKeySpace(classes, m_keyScheduleMode);

    QString summary;
    summary += tr("  密钥扩展读法             = %1\n")
                   .arg(QString::fromUtf8(sdes::describeKeyScheduleMode(m_keyScheduleMode)));
    summary += tr("  密钥总数                 = %1\n").arg(space.keySpaceSize);
    summary += tr("  不同 (k1,k2) 组合数      = %1\n").arg(space.distinctRoundKeyPairs);
    summary += tr("  不同加密映射个数         = %1\n").arg(space.distinctPermutations);
    summary += tr("  单元素等价类个数         = %1\n").arg(space.trivialClassCount);
    summary += tr("  多元素等价类个数         = %1\n").arg(space.nontrivialClassCount);
    summary += tr("  最大等价类大小           = %1\n").arg(space.largestClassSize);
    summary += tr("  平均等价类大小           = %1\n")
                   .arg(QString::number(space.averageClassSize, 'f', 4));
    summary += tr("  有效密钥位数             = %1 bit\n").arg(space.effectiveKeyBits);
    summary += tr("  分析耗时                 = %1 毫秒\n")
                   .arg(QString::number(space.elapsedMs, 'f', 1));

    if (space.nontrivialClassCount == 0) {
        summary += tr("\n结论：1024 个密钥的加密映射两两不同，不存在「对任意明文都等价」的密钥对。"
                      "但注意这并不矛盾 —— 对某个固定明文，仍然会有多个密钥给出相同密文。");
    } else {
        summary += tr("\n结论：存在 %1 个多元素等价类，说明当前读法下密钥扩展丢失了信息，"
                      "实际有效密钥位数只有 %2 bit。")
                       .arg(space.nontrivialClassCount)
                       .arg(space.effectiveKeyBits);
    }
    m_keySpaceSummary->setPlainText(summary);
}

// -----------------------------------------------------------------------------
//  菜单
// -----------------------------------------------------------------------------

void MainWindow::createMenus() {
    QMenu* settingsMenu = menuBar()->addMenu(tr("设置(&S)"));
    QMenu* modeMenu = settingsMenu->addMenu(tr("密钥扩展读法(&K)"));

    auto* group = new QActionGroup(this);
    group->setExclusive(true);

    auto* textbookAction = modeMenu->addAction(tr("教材递进式（k2 在 k1 基础上再左移 2 位）"));
    textbookAction->setCheckable(true);
    textbookAction->setChecked(true);
    group->addAction(textbookAction);

    auto* literalAction = modeMenu->addAction(tr("公式字面式（k2 对 P10(K) 直接左移 2 位）"));
    literalAction->setCheckable(true);
    group->addAction(literalAction);

    connect(textbookAction, &QAction::triggered, this, [this]() {
        m_keyScheduleMode = sdes::KeyScheduleMode::TextbookProgressive;
        refreshVectorTable();
        statusBar()->showMessage(tr("已切换为：%1").arg(
            QString::fromUtf8(sdes::describeKeyScheduleMode(m_keyScheduleMode))));
    });
    connect(literalAction, &QAction::triggered, this, [this]() {
        m_keyScheduleMode = sdes::KeyScheduleMode::LiteralFormula;
        refreshVectorTable();
        statusBar()->showMessage(tr("已切换为：%1").arg(
            QString::fromUtf8(sdes::describeKeyScheduleMode(m_keyScheduleMode))));
    });

    settingsMenu->addSeparator();
    QMenu* sBoxMenu = settingsMenu->addMenu(tr("S 盒版本(&B)"));
    auto* sBoxGroup = new QActionGroup(this);
    sBoxGroup->setExclusive(true);

    auto* homeworkBoxAction = sBoxMenu->addAction(tr("作业指定版本（SBox_2 按 PPT 修改）"));
    homeworkBoxAction->setCheckable(true);
    homeworkBoxAction->setChecked(true);
    sBoxGroup->addAction(homeworkBoxAction);

    auto* textbookBoxAction = sBoxMenu->addAction(tr("Schneier 教材原始版本（用于自检）"));
    textbookBoxAction->setCheckable(true);
    sBoxGroup->addAction(textbookBoxAction);

    connect(homeworkBoxAction, &QAction::triggered, this, [this]() {
        m_sBoxes = sdes::SBoxSet::homework();
        refreshVectorTable();
        statusBar()->showMessage(tr("S 盒已切换为作业指定版本。"));
    });
    connect(textbookBoxAction, &QAction::triggered, this, [this]() {
        m_sBoxes = sdes::SBoxSet::textbook();
        refreshVectorTable();
        statusBar()->showMessage(tr("S 盒已切换为教材原始版本（K=1010000010, P=10010111 应得 00111000）。"));
    });

    QMenu* helpMenu = menuBar()->addMenu(tr("帮助(&H)"));
    QAction* aboutAction = helpMenu->addAction(tr("关于"));
    connect(aboutAction, &QAction::triggered, this, [this]() {
        QMessageBox::information(
            this, tr("关于"),
            tr("<b>S-DES 加解密程序</b><br><br>"
               "分组长度 8 bit，密钥长度 10 bit。<br>"
               "加密：C = IP⁻¹(f_k2(SW(f_k1(IP(P)))))<br>"
               "解密：P = IP⁻¹(f_k1(SW(f_k2(IP(C)))))<br><br>"
               "信息安全导论 · 第 5 次课作业"));
    });
}
