#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QAtomicInteger>
#include <QElapsedTimer>
#include <QFutureWatcher>
#include <QMainWindow>
#include <QVector>

class QPlainTextEdit;
class QLineEdit;
class QLabel;
class QTableWidget;
class QProgressBar;
class QSpinBox;
class QPushButton;
class QTimer;

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
    void onBruteForce();        // 启动多线程暴力破解（单次）
    void onBruteFinished();     // 破解完成回调
    void onStressTest();        // 批量压力测试：连续遍历密钥空间 N 次
    void onStressFinished();    // 压力测试完成回调
    void onStressTick();        // 压力测试进度刷新（每 100 ms）

    // Tab5
    void onClosureTest();       // 枚举指定 (P,C) 的全部密钥
    void onKeyEquivalence();    // ① 密钥等价类分析
    void onPlaintextCollision();// ② 明文维度碰撞检测
    void onCipherProfile();     // ③ 全空间 (P,C) 匹配密钥数分布 + 结论
    void onFullAnalysis();      // 第5关完整分析报告（①②③+结论）

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
    QLineEdit* tab3_hexOut_ = nullptr;
    QLineEdit* tab3_hexIn_ = nullptr;
    QPlainTextEdit* tab3_decOut_ = nullptr;

    // Tab4 控件
    QVector<QLineEdit*> tab4_plainEdits_;
    QVector<QLineEdit*> tab4_cipherEdits_;
    QLabel* tab4_status_ = nullptr;
    QPlainTextEdit* tab4_result_ = nullptr;
    QSpinBox* tab4_iterSpin_ = nullptr;      // 压力测试遍历次数
    QProgressBar* tab4_progress_ = nullptr;  // 进度条
    QLabel* tab4_timeLabel_ = nullptr;       // 实时计时 / 进度文字
    QPushButton* tab4_crackBtn_ = nullptr;   // 单次破解按钮
    QPushButton* tab4_stressBtn_ = nullptr;  // 压力测试按钮

    // Tab5 控件
    QLineEdit* tab5_keyEdit_ = nullptr;
    QLineEdit* tab5_plainEdit_ = nullptr;
    QLineEdit* tab5_cipherEdit_ = nullptr;
    QPlainTextEdit* tab5_analysisOut_ = nullptr;

    // 单次暴力破解异步任务
    QFutureWatcher<uint16_t>* bruteWatcher_ = nullptr;
    QElapsedTimer* bruteTimer_ = nullptr;  // 破解计时
    QVector<std::pair<uint8_t, uint8_t>> brutePairs_;

    // 压力测试（批量遍历密钥空间）状态
    QFutureWatcher<void>* stressWatcher_ = nullptr;
    QTimer* stressUiTimer_ = nullptr;
    QElapsedTimer* stressTimer_ = nullptr;
    QAtomicInteger<long long> stressDoneKeys_{0};  // 已尝试的密钥次数
    long long stressTotalKeys_ = 0;                // 总密钥尝试次数
    long long stressIterations_ = 0;               // 遍历次数
    int stressThreads_ = 0;
};

#endif // MAINWINDOW_H
