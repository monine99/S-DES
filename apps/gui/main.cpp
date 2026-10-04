// =============================================================================
//  apps/gui/main.cpp
//  S-DES 图形界面入口
// =============================================================================

#include <QApplication>

#include "main_window.hpp"

int main(int argc, char** argv) {
    QApplication application(argc, argv);
    QApplication::setApplicationName(QStringLiteral("S-DES 加解密程序"));
    QApplication::setApplicationVersion(QStringLiteral("1.0"));
    QApplication::setOrganizationName(QStringLiteral("信息安全导论作业"));

    MainWindow window;
    window.show();

    return QApplication::exec();
}
