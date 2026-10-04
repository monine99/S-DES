// =============================================================================
//  apps/gui/main_window.hpp
//  S-DES 图形界面主窗口
//
//  界面按作业的五个关卡分成五个标签页：
//      1. 基本加解密   —— 8 bit 明文 + 10 bit 密钥，带完整中间过程展示
//      2. 交叉测试     —— 标准测试向量表，可一键复制成 Markdown
//      3. 字符串加解密 —— 按 1 Byte 分组处理任意文本
//      4. 暴力破解     —— 多线程后台破解，带进度、时间戳与耗时
//      5. 密钥分析     —— 密钥碰撞统计与密钥空间整体结构
// =============================================================================

#pragma once

#include <QMainWindow>
#include <QThread>
#include <vector>

#include "sdes/brute_force.hpp"
#include "sdes/cipher.hpp"

class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QProgressBar;
class QPushButton;
class QSpinBox;
class QTableWidget;

/// 在后台线程里跑暴力破解，避免界面卡死。
/// 进度通过信号发回主线程（跨线程 emit 会自动排队投递）；
/// 结果通过 result() 读取，只在 QThread::finished 之后才安全。
class BruteForceTask : public QThread {
    Q_OBJECT

public:
    BruteForceTask(std::vector<sdes::KnownPair> pairs, sdes::BruteForceOptions options,
                   QObject* parent = nullptr);

    const sdes::BruteForceResult& result() const { return result_; }

signals:
    void progressChanged(int tested, int total);

protected:
    void run() override;

private:
    std::vector<sdes::KnownPair> pairs_;
    sdes::BruteForceOptions options_;
    sdes::BruteForceResult result_;
};

/// 主窗口。
class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);

private slots:
    void onBlockEncryptClicked();
    void onBlockDecryptClicked();
    void onBlockSwapClicked();
    void onTextEncryptClicked();
    void onTextDecryptClicked();
    void onTextSwapClicked();
    void onBruteForceClicked();
    void onBruteProgress(int tested, int total);
    void onBruteFinished();
    void onAnalyseClicked();
    void onKeySpaceClicked();
    void onCopyVectorsClicked();

private:
    QWidget* createBasicTab();
    QWidget* createCrossTestTab();
    QWidget* createTextTab();
    QWidget* createBruteForceTab();
    QWidget* createAnalysisTab();
    void createMenus();
    void refreshVectorTable();

    void reportError(const QString& message);
    sdes::Cipher makeCipher(const sdes::Block10& key) const;
    /// 读取密钥输入框，失败时弹提示并返回 false。
    bool readKeyFrom(QLineEdit* field, sdes::Block10& keyOut);
    /// 读取 8 bit 分组输入框。
    bool readBlockFrom(QLineEdit* field, sdes::Block8& blockOut);

    // ---- 1. 基本加解密 ----
    QLineEdit* m_keyInput = nullptr;
    QLineEdit* m_plainInput = nullptr;
    QLineEdit* m_cipherOutput = nullptr;
    QLabel* m_basicStatus = nullptr;
    QPlainTextEdit* m_basicTrace = nullptr;

    // ---- 2. 交叉测试 ----
    QTableWidget* m_vectorTable = nullptr;

    // ---- 3. 字符串加解密 ----
    QLineEdit* m_textKey = nullptr;
    QPlainTextEdit* m_textInput = nullptr;
    QPlainTextEdit* m_textOutput = nullptr;
    QLabel* m_textStatus = nullptr;

    // ---- 4. 暴力破解 ----
    QPlainTextEdit* m_brutePairs = nullptr;
    QSpinBox* m_bruteThreads = nullptr;
    QPushButton* m_bruteButton = nullptr;
    QProgressBar* m_bruteProgress = nullptr;
    QPlainTextEdit* m_bruteLog = nullptr;
    BruteForceTask* m_bruteTask = nullptr;

    // ---- 5. 密钥分析 ----
    QLineEdit* m_analysisPlain = nullptr;
    QPlainTextEdit* m_analysisSummary = nullptr;
    QTableWidget* m_analysisTable = nullptr;
    QPlainTextEdit* m_keySpaceSummary = nullptr;

    // ---- 全局设置 ----
    sdes::KeyScheduleMode m_keyScheduleMode = sdes::kDefaultKeyScheduleMode;
    sdes::SBoxSet m_sBoxes = sdes::SBoxSet::homework();
};
