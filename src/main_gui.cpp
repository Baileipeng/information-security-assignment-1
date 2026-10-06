// ---------------------------------------------------------------------------
// S-DES GUI 程序入口
//
// 用法:
//   sdes_gui                     正常启动图形界面
//   sdes_gui --capture <目录>    自动截图模式：依次运行第 1~5 关的操作并
//                                保存窗口截图到指定目录，用于实验报告配图
// ---------------------------------------------------------------------------
#include <QApplication>
#include <QDir>
#include <QMetaObject>
#include <QPixmap>
#include <QScreen>
#include <QTabWidget>
#include <QTimer>
#include <QWindow>

#include <functional>

#include "mainwindow.h"

namespace {

// 抓取窗口（含系统标题栏）并保存为 PNG。
// 为兼容高 DPI 缩放：先整屏截图，再按“物理像素/逻辑坐标”的比例
// 换算出窗口边框区域进行裁剪，避免截入任务栏或裁掉窗口边缘。
void captureWindow(MainWindow& window, const QString& path) {
    window.raise();
    window.activateWindow();

    QScreen* screen = window.screen();
    QPixmap full = screen->grabWindow(0); // 整屏截图
    QPixmap shot;
    if (window.windowHandle() && !full.isNull()) {
        QRect frame = window.windowHandle()->frameGeometry(); // 逻辑坐标
        QRect avail = screen->geometry();
        double sx = double(full.width()) / double(avail.width());
        double sy = double(full.height()) / double(avail.height());
        QRect phys(qRound(frame.x() * sx), qRound(frame.y() * sy),
                   qRound(frame.width() * sx), qRound(frame.height() * sy));
        shot = full.copy(phys);
    }
    if (shot.isNull()) {
        shot = window.grab(); // 兜底：直接渲染窗口控件
    }
    shot.save(path, "PNG");
    qInfo().noquote() << "已保存截图:" << path;
}

// 触发 MainWindow 的私有槽函数（槽函数已注册到元对象，可通过名称调用）
void invoke(MainWindow& window, const char* slot) {
    QMetaObject::invokeMethod(&window, slot, Qt::DirectConnection);
}

} // namespace

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    MainWindow window;

    // ---- 自动截图模式 ----
    if (argc >= 2 && QString(argv[1]) == "--capture") {
        const QString outDir = (argc >= 3) ? QString(argv[2]) : QString("screenshots");
        QDir().mkpath(outDir);

        // 按屏幕可用区域自适应窗口大小（避开任务栏），保证内容完整显示
        QRect avail = window.screen()->availableGeometry();
        window.resize(qMin(1150, avail.width() - 60), qMin(820, avail.height() - 60));
        window.move(avail.x() + 20, avail.y() + 10);
        window.show();

        QTabWidget* tabs = window.findChild<QTabWidget*>();

        // 以延时链方式依次执行各关卡操作并截图
        const int step = 900; // 每步间隔（毫秒）
        int t = step;

        auto schedule = [&](int delay, std::function<void()> fn) {
            QTimer::singleShot(delay, [fn]() { fn(); });
        };

        // 第 1 关：加密 + 解密
        schedule(t, [&]() {
            tabs->setCurrentIndex(0);
            invoke(window, "onEncryptBits");
        });
        schedule(t + 300, [&]() { captureWindow(window, outDir + "/01_关卡1_基本测试_加密.png"); });
        schedule(t + 600, [&]() { invoke(window, "onDecryptBits"); });
        schedule(t + 900, [&]() { captureWindow(window, outDir + "/02_关卡1_基本测试_解密.png"); });

        // 第 2 关：交叉测试向量表
        t += 1300;
        schedule(t, [&]() {
            tabs->setCurrentIndex(1);
            invoke(window, "onGenerateVectors");
        });
        schedule(t + 400, [&]() { captureWindow(window, outDir + "/03_关卡2_交叉测试向量表.png"); });

        // 第 3 关：文本加密 + 解密
        t += 900;
        schedule(t, [&]() {
            tabs->setCurrentIndex(2);
            invoke(window, "onEncryptText");
        });
        schedule(t + 300, [&]() { invoke(window, "onDecryptText"); });
        schedule(t + 600, [&]() { captureWindow(window, outDir + "/04_关卡3_扩展功能_文本加解密.png"); });

        // 第 4 关：多线程暴力破解（等待计算完成）
        t += 1200;
        schedule(t, [&]() {
            tabs->setCurrentIndex(3);
            invoke(window, "onBruteForce");
        });
        schedule(t + 3000, [&]() { captureWindow(window, outDir + "/05_关卡4_暴力破解.png"); });

        // 第 5 关：封闭测试（单点枚举 + 全文分析）
        t += 3600;
        schedule(t, [&]() {
            tabs->setCurrentIndex(4);
            invoke(window, "onClosureTest");
        });
        schedule(t + 400, [&]() { captureWindow(window, outDir + "/06_关卡5_封闭测试_单点枚举.png"); });
        schedule(t + 700, [&]() { invoke(window, "onFullAnalysis"); });
        schedule(t + 2400, [&]() { captureWindow(window, outDir + "/07_关卡5_封闭测试_全文分析.png"); });

        // 结束
        schedule(t + 3000, [&]() { qApp->quit(); });
        return app.exec();
    }

    // ---- 正常交互模式 ----
    window.show();
    return app.exec();
}
