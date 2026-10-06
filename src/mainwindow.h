#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QElapsedTimer>
#include <QFutureWatcher>
#include <QMainWindow>
#include <QVector>

class QPlainTextEdit;
class QLineEdit;
class QLabel;
class QTableWidget;

// ---------------------------------------------------------------------------
// 主窗口：用 QTabWidget 组织 5 个关卡页面
//   Tab1 基本测试 | Tab2 交叉测试 | Tab3 扩展功能 | Tab4 暴力破解 | Tab5 封闭测试
// ---------------------------------------------------------------------------
class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);

private:
    // ---------------------- 界面构建 ----------------------
    QWidget* buildTab1Basic();
    QWidget* buildTab2Cross();
    QWidget* buildTab3Text();
    QWidget* buildTab4Brute();
    QWidget* buildTab5Closure();

    // ---------------------- 工具函数 ----------------------
    // 校验二进制串并转换为数值；失败时弹提示返回 false
    static bool readBits(QLineEdit* edit, int bits, uint16_t& out, const QString& name);
    static void setStatus(QLabel* label, const QString& text);

private slots:
    // Tab1
    void onEncryptBits();
    void onDecryptBits();

    // Tab2
    void onGenerateVectors();   // 生成 (P, K) -> (C, k1, k2) 交叉测试向量表

    // Tab3
    void onEncryptText();
    void onDecryptText();

    // Tab4
    void onBruteForce();        // 启动多线程暴力破解
    void onBruteFinished();     // 破解完成回调

    // Tab5
    void onClosureTest();       // 枚举指定 (P,C) 的全部密钥
    void onFullAnalysis();      // 全明文空间多重密钥统计

private:
    // Tab1 控件
    QLineEdit* tab1_keyEdit_ = nullptr;
    QLineEdit* tab1_plainEdit_ = nullptr;
    QLineEdit* tab1_cipherEdit_ = nullptr;
    QLineEdit* tab1_outEdit_ = nullptr;
    QLabel* tab1_status_ = nullptr;
    QLabel* tab1_subKeys_ = nullptr;

    // Tab3 控件
    QLineEdit* tab3_keyEdit_ = nullptr;
    QPlainTextEdit* tab3_plainEdit_ = nullptr;
    QPlainTextEdit* tab3_binOut_ = nullptr;
    QLineEdit* tab3_hexIn_ = nullptr;
    QPlainTextEdit* tab3_decOut_ = nullptr;

    // Tab4 控件
    QVector<QLineEdit*> tab4_plainEdits_;
    QVector<QLineEdit*> tab4_cipherEdits_;
    QLabel* tab4_status_ = nullptr;
    QPlainTextEdit* tab4_result_ = nullptr;

    // Tab5 控件
    QLineEdit* tab5_keyEdit_ = nullptr;
    QLineEdit* tab5_plainEdit_ = nullptr;
    QLineEdit* tab5_cipherEdit_ = nullptr;
    QPlainTextEdit* tab5_result_ = nullptr;
    QPlainTextEdit* tab5_analysisOut_ = nullptr;

    // 暴力破解异步任务
    QFutureWatcher<uint16_t>* bruteWatcher_ = nullptr;
    QElapsedTimer* bruteTimer_ = nullptr;  // 破解计时
    QVector<std::pair<uint8_t, uint8_t>> brutePairs_;
};

#endif // MAINWINDOW_H
