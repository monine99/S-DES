// =============================================================================
//  apps/gui/main.cpp
//  S-DES 图形界面入口
// =============================================================================

#include <QApplication>

#include "main_window.hpp"
#include "theme.hpp"

int main(int argc, char** argv) {
    QApplication application(argc, argv);
    QApplication::setApplicationName(QStringLiteral("S-DES 加解密程序"));
    QApplication::setApplicationVersion(QStringLiteral("1.1"));
    QApplication::setOrganizationName(QStringLiteral("信息安全导论作业"));

    // 统一视觉主题：必须在创建任何窗口之前套上，否则首帧会闪一下默认样式
    gui::applyTheme(application);

    MainWindow window;
    window.show();

    return QApplication::exec();
}
