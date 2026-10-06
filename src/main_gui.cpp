// ---------------------------------------------------------------------------
// S-DES GUI 程序入口
// ---------------------------------------------------------------------------
#include <QApplication>

#include "mainwindow.h"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    MainWindow window;
    window.show();

    return app.exec();
}
