// =============================================================================
//  apps/gui/theme.cpp
//  S-DES 图形界面的视觉主题
//
//  【设计目标】把默认的 Qt Widgets 观感（灰色、直角、凹陷立体边框）换成
//  现代的浅色卡片式界面：浅灰窗口底 + 纯白卡片、淡边框、圆角、克制的强调色、
//  充足的留白。
//
//  【配色令牌】全部颜色集中在下面的 QSS 里，含义如下：
//      #F6F7F9  窗口底色（最底层）
//      #FFFFFF  卡片 / 表格 / 输入框（浮起层）
//      #FBFCFD  代码与结果区（下沉层，区别于普通输入框）
//      #E3E6EA  常规边框（很淡）
//      #D8DCE1  输入类控件的边框（略深一点，保证可辨识）
//      #1F2328  主文字
//      #6B7280  次要文字（表头、说明）
//      #9AA1AA  弱化文字（占位符、禁用态）
//      #2563EB  强调色 —— 只用在主操作按钮、选中标签、聚焦边框上
//      #EFF4FF  强调色的浅底（菜单项悬停、表格选中行）
//
//  【为什么还要设 QPalette】样式表管不到的地方（原生绘制路径、某些下拉列表
//  内部）会退回调色板取值，两边保持一致才不会出现突兀的灰色块。
// =============================================================================

#include "theme.hpp"

#include <QApplication>
#include <QColor>
#include <QFont>
#include <QFontDatabase>
#include <QPalette>
#include <QString>
#include <QStringList>
#include <QStyleFactory>

namespace {

/// 全部视觉规则。
QString styleSheet() {
    return QStringLiteral(R"QSS(
/* ===========================================================================
   全局
   =========================================================================== */
QWidget {
    color: #1F2328;
    font-family: "Microsoft YaHei UI", "Microsoft YaHei", "Segoe UI", sans-serif;
    font-size: 13px;
}

QMainWindow, QDialog {
    background-color: #F6F7F9;
}

/* ===========================================================================
   顶部标签页
   =========================================================================== */
/* 整个 QTabWidget 铺白底，这样标签栏所在的整条都是白的（QTabBar 本身只占
   标签宽度，靠它自己铺不满）；内容区 pane 再压一层浅灰，形成层次。 */
QTabWidget {
    background-color: #FFFFFF;
}

QTabWidget::pane {
    border: none;
    border-top: 1px solid #E3E6EA;
    background-color: #F6F7F9;
}

QTabBar {
    background: transparent;
    qproperty-drawBase: 0;
}

QTabBar::tab {
    background: transparent;
    color: #6B7280;
    border: none;
    border-bottom: 2px solid transparent;
    padding: 9px 20px;
    margin-right: 2px;
    font-weight: 500;
}

QTabBar::tab:hover {
    color: #1F2328;
    background-color: #EDF0F3;
    border-top-left-radius: 7px;
    border-top-right-radius: 7px;
}

QTabBar::tab:selected {
    color: #2563EB;
    border-bottom: 2px solid #2563EB;
    font-weight: 600;
}

QTabBar::tab:disabled {
    color: #B6BCC4;
}

/* ===========================================================================
   卡片（QGroupBox）
   标题放在卡片内部左上角，不在边框线上压出一条缺口
   =========================================================================== */
QGroupBox {
    background-color: #FFFFFF;
    border: 1px solid #E3E6EA;
    border-radius: 10px;
    margin-top: 0px;
    padding: 36px 18px 18px 18px;
    font-weight: 600;
    color: #1F2328;
}

QGroupBox::title {
    subcontrol-origin: border;
    subcontrol-position: top left;
    left: 18px;
    top: 11px;
    padding: 0px;
    color: #1F2328;
}

/* ===========================================================================
   按钮
   =========================================================================== */
QPushButton {
    background-color: #FFFFFF;
    color: #1F2328;
    border: 1px solid #D8DCE1;
    border-radius: 7px;
    padding: 7px 18px;
    font-weight: 500;
    min-height: 19px;
}

QPushButton:hover {
    background-color: #F4F6F8;
    border-color: #C2C9D2;
}

QPushButton:pressed {
    background-color: #E8EBEF;
}

QPushButton:disabled {
    background-color: #F6F7F9;
    border-color: #E6E9ED;
    color: #A8AFB8;
}

/* 主操作按钮：整个界面里唯一大面积使用强调色的地方 */
QPushButton[primary="true"] {
    background-color: #2563EB;
    border-color: #2563EB;
    color: #FFFFFF;
    font-weight: 600;
}

QPushButton[primary="true"]:hover {
    background-color: #1D4ED8;
    border-color: #1D4ED8;
}

QPushButton[primary="true"]:pressed {
    background-color: #1A44BE;
    border-color: #1A44BE;
}

QPushButton[primary="true"]:disabled {
    background-color: #A9C1F2;
    border-color: #A9C1F2;
    color: #FFFFFF;
}

/* ===========================================================================
   单行输入
   =========================================================================== */
QLineEdit {
    background-color: #FFFFFF;
    border: 1px solid #D8DCE1;
    border-radius: 7px;
    padding: 7px 11px;
    selection-background-color: #BFD4FB;
    selection-color: #1F2328;
}

QLineEdit:hover {
    border-color: #C2C9D2;
}

QLineEdit:focus {
    border: 1px solid #2563EB;
}

QLineEdit:read-only {
    background-color: #F7F8FA;
    color: #4B5563;
}

QLineEdit:disabled {
    background-color: #F6F7F9;
    color: #A8AFB8;
}

/* 位串输入框用等宽字体，相邻两位的 0/1 更容易数 */
QLineEdit[mono="true"] {
    font-family: "Cascadia Mono", "Consolas", "Courier New", monospace;
    font-size: 14px;
    padding: 6px 11px;
}

/* ===========================================================================
   多行文本
   =========================================================================== */
QPlainTextEdit, QTextEdit {
    background-color: #FBFCFD;
    border: 1px solid #E3E6EA;
    border-radius: 8px;
    padding: 12px;
    selection-background-color: #BFD4FB;
    selection-color: #1F2328;
}

QPlainTextEdit:focus, QTextEdit:focus {
    border: 1px solid #C9D4E4;
}

/* 展示中间过程 / 结果的大文本区用等宽字体，字段对齐不会错行 */
QPlainTextEdit[mono="true"], QTextEdit[mono="true"] {
    font-family: "Cascadia Mono", "Consolas", "Courier New", monospace;
    font-size: 12px;
    line-height: 150%;
}

/* ===========================================================================
   表格
   =========================================================================== */
QTableWidget, QTableView {
    background-color: #FFFFFF;
    alternate-background-color: #FAFBFC;
    border: 1px solid #E3E6EA;
    border-radius: 8px;
    gridline-color: #F0F2F5;
    selection-background-color: #EFF4FF;
    selection-color: #1F2328;
    outline: none;
}

QTableWidget::item, QTableView::item {
    padding: 6px 9px;
    border: none;
}

QTableWidget::item:selected, QTableView::item:selected {
    background-color: #EFF4FF;
    color: #1F2328;
}

QHeaderView {
    background-color: transparent;
    border: none;
}

QHeaderView::section {
    background-color: #F7F8FA;
    color: #6B7280;
    border: none;
    border-bottom: 1px solid #E3E6EA;
    border-right: 1px solid #F0F2F5;
    padding: 9px 9px;
    font-weight: 600;
}

QHeaderView::section:hover {
    background-color: #F1F3F6;
    color: #4B5563;
}

QTableCornerButton::section {
    background-color: #F7F8FA;
    border: none;
    border-bottom: 1px solid #E3E6EA;
}

/* 分析页的密钥列表列用等宽，密钥上下对齐才好比对 */
QTableWidget[mono="true"] {
    font-family: "Cascadia Mono", "Consolas", "Courier New", monospace;
    font-size: 12px;
}

/* ===========================================================================
   进度条
   =========================================================================== */
QProgressBar {
    background-color: #EEF1F4;
    border: none;
    border-radius: 9px;
    min-height: 18px;
    max-height: 18px;
    text-align: center;
    color: #4B5563;
    font-size: 11px;
}

QProgressBar::chunk {
    background-color: #2563EB;
    border-radius: 9px;
}

/* ===========================================================================
   数字框
   =========================================================================== */
QSpinBox, QDoubleSpinBox {
    background-color: #FFFFFF;
    border: 1px solid #D8DCE1;
    border-radius: 7px;
    padding: 6px 8px;
    min-width: 58px;
    selection-background-color: #BFD4FB;
}

QSpinBox:hover, QDoubleSpinBox:hover {
    border-color: #C2C9D2;
}

QSpinBox:focus, QDoubleSpinBox:focus {
    border-color: #2563EB;
}

QSpinBox::up-button, QSpinBox::down-button,
QDoubleSpinBox::up-button, QDoubleSpinBox::down-button {
    background: transparent;
    border: none;
    width: 16px;
}

QSpinBox::up-arrow, QDoubleSpinBox::up-arrow {
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-bottom: 4px solid #6B7280;
    width: 0px;
    height: 0px;
}

QSpinBox::down-arrow, QDoubleSpinBox::down-arrow {
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 4px solid #6B7280;
    width: 0px;
    height: 0px;
}

/* ===========================================================================
   菜单栏与菜单
   =========================================================================== */
QMenuBar {
    background-color: #FFFFFF;
    border-bottom: 1px solid #E3E6EA;
    padding: 3px 6px;
}

QMenuBar::item {
    background: transparent;
    padding: 6px 13px;
    border-radius: 6px;
    color: #4B5563;
}

QMenuBar::item:selected {
    background-color: #F1F3F6;
    color: #1F2328;
}

QMenuBar::item:pressed {
    background-color: #E8EBEF;
}

QMenu {
    background-color: #FFFFFF;
    border: 1px solid #E3E6EA;
    border-radius: 8px;
    padding: 6px;
}

QMenu::item {
    padding: 7px 26px 7px 14px;
    border-radius: 6px;
    color: #1F2328;
}

QMenu::item:selected {
    background-color: #EFF4FF;
    color: #2563EB;
}

QMenu::item:disabled {
    color: #A8AFB8;
}

QMenu::separator {
    height: 1px;
    background-color: #EEF0F2;
    margin: 5px 8px;
}

QMenu::indicator {
    width: 14px;
    height: 14px;
    margin-left: 6px;
}

/* ===========================================================================
   状态栏
   =========================================================================== */
QStatusBar {
    background-color: #FFFFFF;
    border-top: 1px solid #E3E6EA;
    color: #6B7280;
    padding: 3px 10px;
}

QStatusBar::item {
    border: none;
}

/* ===========================================================================
   滚动条：细、圆角、无箭头
   =========================================================================== */
QScrollBar:vertical {
    background: transparent;
    width: 11px;
    margin: 2px 2px 2px 0px;
}

QScrollBar::handle:vertical {
    background: #C9CED6;
    border-radius: 4px;
    min-height: 32px;
}

QScrollBar::handle:vertical:hover {
    background: #A9B0BA;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
    background: transparent;
}

QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    background: transparent;
}

QScrollBar:horizontal {
    background: transparent;
    height: 11px;
    margin: 0px 2px 2px 2px;
}

QScrollBar::handle:horizontal {
    background: #C9CED6;
    border-radius: 4px;
    min-width: 32px;
}

QScrollBar::handle:horizontal:hover {
    background: #A9B0BA;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
    background: transparent;
}

QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
    background: transparent;
}

QScrollBar::corner {
    background: transparent;
}

/* ===========================================================================
   文字标签：按用途分三级
   =========================================================================== */
QLabel {
    background: transparent;
    color: #1F2328;
}

QLabel[role="hint"] {
    color: #6B7280;
}

QLabel[role="status"] {
    color: #4B5563;
}

QLabel[role="value"] {
    color: #1F2328;
    font-weight: 600;
}

/* ===========================================================================
   提示气泡
   =========================================================================== */
QToolTip {
    background-color: #1F2328;
    color: #FFFFFF;
    border: none;
    border-radius: 6px;
    padding: 6px 10px;
}

/* ===========================================================================
   分组之间的细分隔线
   =========================================================================== */
QFrame[role="separator"] {
    background-color: #EEF0F2;
    max-height: 1px;
    border: none;
}
)QSS");
}

}  // namespace

namespace gui {

void applyTheme(QApplication& application) {
    // 固定使用 Fusion 风格打底：系统原生风格在不同 Windows 版本上差异很大，
    // 会让样式表的表现不稳定。Fusion 保证各平台/各版本起点一致。
    if (QStyle* fusion = QStyleFactory::create(QStringLiteral("Fusion"))) {
        application.setStyle(fusion);
    }

    // 调色板兜底：样式表覆盖不到的原生绘制路径会退回这里取值，
    // 两边一致才不会突然冒出一块系统灰。
    QPalette palette = application.palette();
    palette.setColor(QPalette::Window, QColor(QStringLiteral("#F6F7F9")));
    palette.setColor(QPalette::WindowText, QColor(QStringLiteral("#1F2328")));
    palette.setColor(QPalette::Base, QColor(QStringLiteral("#FFFFFF")));
    palette.setColor(QPalette::AlternateBase, QColor(QStringLiteral("#FAFBFC")));
    palette.setColor(QPalette::Text, QColor(QStringLiteral("#1F2328")));
    palette.setColor(QPalette::Button, QColor(QStringLiteral("#FFFFFF")));
    palette.setColor(QPalette::ButtonText, QColor(QStringLiteral("#1F2328")));
    palette.setColor(QPalette::BrightText, QColor(QStringLiteral("#FFFFFF")));
    palette.setColor(QPalette::Highlight, QColor(QStringLiteral("#2563EB")));
    palette.setColor(QPalette::HighlightedText, QColor(QStringLiteral("#FFFFFF")));
    palette.setColor(QPalette::ToolTipBase, QColor(QStringLiteral("#1F2328")));
    palette.setColor(QPalette::ToolTipText, QColor(QStringLiteral("#FFFFFF")));
    palette.setColor(QPalette::PlaceholderText, QColor(QStringLiteral("#9AA1AA")));
    palette.setColor(QPalette::Disabled, QPalette::Text, QColor(QStringLiteral("#A8AFB8")));
    palette.setColor(QPalette::Disabled, QPalette::WindowText, QColor(QStringLiteral("#A8AFB8")));
    palette.setColor(QPalette::Disabled, QPalette::ButtonText, QColor(QStringLiteral("#A8AFB8")));
    application.setPalette(palette);

    // 挑一个系统里确实存在的中文友好字体，避免落到难看的默认衬线字体上。
    const QStringList preferredFamilies{
        QStringLiteral("Microsoft YaHei UI"),
        QStringLiteral("Microsoft YaHei"),
        QStringLiteral("Segoe UI"),
    };
    const QStringList availableFamilies = QFontDatabase::families();
    QFont baseFont = application.font();
    for (const QString& family : preferredFamilies) {
        if (availableFamilies.contains(family)) {
            baseFont.setFamily(family);
            break;
        }
    }
    baseFont.setPointSizeF(9.75);  // 约等于 13px，与样式表里的 font-size 对齐
    application.setFont(baseFont);

    application.setStyleSheet(styleSheet());
}

}  // namespace gui
