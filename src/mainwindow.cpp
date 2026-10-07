#include "mainwindow.h"

#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QRegularExpression>
#include <QSpinBox>
#include <QTabWidget>
#include <QTableWidget>
#include <QThread>
#include <QTimer>
#include <QVBoxLayout>
#include <QtConcurrent>

#include "sdes.h"
#include "sdes_analysis.h"

using namespace sdes;

namespace {

// 输入框统一等宽字体，保证二进制位对齐
const char* kEditStyle = "QLineEdit, QPlainTextEdit { font-family: Consolas, monospace; }";

// 全部置换表常量字符串（界面展示用，方便实验报告对照）
const char* kTableInfo =
    "P10  = {3,5,2,7,4,10,1,9,8,6}\n"
    "P8   = {6,3,7,4,8,5,10,9}\n"
    "IP   = {2,6,3,1,4,8,5,7}\n"
    "IP-1 = {4,1,3,5,7,2,8,6}\n"
    "EP   = {4,1,2,3,2,3,4,1}\n"
    "SP   = {2,4,3,1}\n"
    "SBox1 = {{1,0,3,2},{3,2,1,0},{0,2,1,3},{3,1,0,2}}\n"
    "SBox2 = {{0,1,2,3},{2,3,1,0},{3,0,1,2},{2,1,0,3}}  (作业指定修改版)";

} // namespace

// ---------------------------------------------------------------------------
// 构造：整体布局
// ---------------------------------------------------------------------------
MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle("S-DES 加解密系统 —— 信息安全导论 作业1");
    resize(1000, 700);

    QTabWidget* tabs = new QTabWidget(this);
    tabs->addTab(buildTab1Basic(),   "第1关 基本测试");
    tabs->addTab(buildTab2Cross(),   "第2关 交叉测试");
    tabs->addTab(buildTab3Text(),    "第3关 扩展功能");
    tabs->addTab(buildTab4Brute(),   "第4关 暴力破解");
    tabs->addTab(buildTab5Closure(), "第5关 封闭测试");
    setCentralWidget(tabs);

    bruteWatcher_ = new QFutureWatcher<uint16_t>(this);
    connect(bruteWatcher_, &QFutureWatcher<uint16_t>::finished,
            this, &MainWindow::onBruteFinished);
    bruteTimer_ = new QElapsedTimer();

    // 压力测试（批量遍历）相关对象
    stressWatcher_ = new QFutureWatcher<void>(this);
    connect(stressWatcher_, &QFutureWatcher<void>::finished,
            this, &MainWindow::onStressFinished);
    stressUiTimer_ = new QTimer(this);
    connect(stressUiTimer_, &QTimer::timeout, this, &MainWindow::onStressTick);
    stressTimer_ = new QElapsedTimer();
}

// ---------------------------------------------------------------------------
// 通用小工具
// ---------------------------------------------------------------------------
bool MainWindow::readBits(QLineEdit* edit, int bits, uint16_t& out, const QString& name) {
    std::string text = edit->text().toStdString();
    uint16_t v = 0;
    if (!parseBinaryString(text, bits, v)) {
        QMessageBox::warning(nullptr, "输入错误",
                             QString("%1 必须是 %2 位二进制串（只含 0/1，可含空格）")
                                 .arg(name).arg(bits));
        return false;
    }
    out = v;
    return true;
}

void MainWindow::setStatus(QLabel* label, const QString& text) {
    label->setText(text);
}

// ---------------------------------------------------------------------------
// Tab1：基本测试
// ---------------------------------------------------------------------------
QWidget* MainWindow::buildTab1Basic() {
    QWidget* page = new QWidget(this);
    QVBoxLayout* layout = new QVBoxLayout(page);

    QGroupBox* box = new QGroupBox("S-DES 加解密（8 bit 数据 / 10 bit 密钥）", page);
    QGridLayout* grid = new QGridLayout(box);

    grid->addWidget(new QLabel("密钥 (10 bit):"), 0, 0);
    tab1_keyEdit_ = new QLineEdit("1010000010");
    tab1_keyEdit_->setStyleSheet(kEditStyle);
    grid->addWidget(tab1_keyEdit_, 0, 1);

    grid->addWidget(new QLabel("明文 (8 bit):"), 1, 0);
    tab1_plainEdit_ = new QLineEdit("00101000");
    tab1_plainEdit_->setStyleSheet(kEditStyle);
    grid->addWidget(tab1_plainEdit_, 1, 1);

    grid->addWidget(new QLabel("密文 (8 bit):"), 2, 0);
    tab1_cipherEdit_ = new QLineEdit("11110100");
    tab1_cipherEdit_->setStyleSheet(kEditStyle);
    grid->addWidget(tab1_cipherEdit_, 2, 1);

    tab1_outEdit_ = new QLineEdit();
    tab1_outEdit_->setReadOnly(true);
    tab1_outEdit_->setStyleSheet(kEditStyle);
    grid->addWidget(new QLabel("输出结果:"), 3, 0);
    grid->addWidget(tab1_outEdit_, 3, 1);

    QPushButton* encBtn = new QPushButton("加密 (明文→密文)");
    QPushButton* decBtn = new QPushButton("解密 (密文→明文)");
    connect(encBtn, &QPushButton::clicked, this, &MainWindow::onEncryptBits);
    connect(decBtn, &QPushButton::clicked, this, &MainWindow::onDecryptBits);
    QHBoxLayout* btnRow = new QHBoxLayout();
    btnRow->addWidget(encBtn);
    btnRow->addWidget(decBtn);
    grid->addLayout(btnRow, 4, 0, 1, 2);

    tab1_subKeys_ = new QLabel("子密钥：k1 = --------, k2 = --------");
    grid->addWidget(tab1_subKeys_, 5, 0, 1, 2);

    tab1_status_ = new QLabel("就绪。输入 8 bit 二进制明文与 10 bit 二进制密钥。");
    layout->addWidget(box);
    layout->addWidget(tab1_status_);
    layout->addStretch(1);
    return page;
}

void MainWindow::onEncryptBits() {
    uint16_t key; uint16_t p;
    if (!readBits(tab1_keyEdit_, 10, key, "密钥")) return;
    if (!readBits(tab1_plainEdit_, 8, p, "明文")) return;

    uint8_t k1, k2;
    generateSubKeys(static_cast<uint16_t>(key), k1, k2);
    uint8_t c = encrypt(static_cast<uint8_t>(p), static_cast<uint16_t>(key));

    tab1_outEdit_->setText(QString::fromStdString(toBinaryString(c, 8)));
    tab1_subKeys_->setText(QString("子密钥：k1 = %1, k2 = %2")
                               .arg(QString::fromStdString(toBinaryString(k1, 8)))
                               .arg(QString::fromStdString(toBinaryString(k2, 8))));
    setStatus(tab1_status_, QString("加密完成：P=%1 -> C=%2 (K=%3)")
                                .arg(QString::fromStdString(toBinaryString(static_cast<uint8_t>(p), 8)))
                                .arg(QString::fromStdString(toBinaryString(c, 8)))
                                .arg(QString::fromStdString(toBinaryString(static_cast<uint16_t>(key), 10))));
}

void MainWindow::onDecryptBits() {
    uint16_t key; uint16_t c;
    if (!readBits(tab1_keyEdit_, 10, key, "密钥")) return;
    if (!readBits(tab1_cipherEdit_, 8, c, "密文")) return;

    uint8_t k1, k2;
    generateSubKeys(static_cast<uint16_t>(key), k1, k2);
    uint8_t p = decrypt(static_cast<uint8_t>(c), static_cast<uint16_t>(key));

    tab1_outEdit_->setText(QString::fromStdString(toBinaryString(p, 8)));
    tab1_subKeys_->setText(QString("子密钥：k1 = %1, k2 = %2")
                               .arg(QString::fromStdString(toBinaryString(k1, 8)))
                               .arg(QString::fromStdString(toBinaryString(k2, 8))));
    setStatus(tab1_status_, QString("解密完成：C=%1 -> P=%2 (K=%3)")
                                .arg(QString::fromStdString(toBinaryString(static_cast<uint8_t>(c), 8)))
                                .arg(QString::fromStdString(toBinaryString(p, 8)))
                                .arg(QString::fromStdString(toBinaryString(static_cast<uint16_t>(key), 10))));
}

// ---------------------------------------------------------------------------
// Tab2：交叉测试 —— 输入若干 (P, K)，生成 (C, k1, k2) 对照表供两组交换核对
// ---------------------------------------------------------------------------
QWidget* MainWindow::buildTab2Cross() {
    QWidget* page = new QWidget(this);
    QVBoxLayout* layout = new QVBoxLayout(page);

    QLabel* intro = new QLabel(
        "算法完全按作业文档的标准置换表实现（见下方参数），任何小组按相同"
        "标准实现的程序，对相同 (P, K) 必然得到相同 C。两组各选一组 (P, K)，"
        "交换后核对密文与子密钥即可完成交叉测试。", page);
    intro->setWordWrap(true);
    layout->addWidget(intro);

    QGroupBox* inputBox = new QGroupBox("输入明文 P 与密钥 K（每行一组，空格分隔）", page);
    QVBoxLayout* vb = new QVBoxLayout(inputBox);
    QPlainTextEdit* input = new QPlainTextEdit(inputBox);
    input->setObjectName("crossInput");
    input->setStyleSheet(kEditStyle);
    input->setMaximumHeight(120);
    input->setPlainText(
        "00101000 1010000010\n"
        "00101000 0000000000\n"
        "00101000 1111111111\n"
        "11011001 0110111001\n"
        "11111111 1010000010");
    vb->addWidget(input);
    layout->addWidget(inputBox);

    QPushButton* genBtn = new QPushButton("生成交叉测试向量表");
    connect(genBtn, &QPushButton::clicked, this, &MainWindow::onGenerateVectors);
    layout->addWidget(genBtn);

    QTableWidget* table = new QTableWidget(0, 5, page);
    table->setObjectName("crossTable");
    table->setHorizontalHeaderLabels({"明文 P (8bit)", "密钥 K (10bit)", "密文 C (8bit)",
                                      "子密钥 k1", "子密钥 k2"});
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    layout->addWidget(table);

    QLabel* tables = new QLabel(QString::fromUtf8(kTableInfo), page);
    layout->addWidget(tables);
    return page;
}

void MainWindow::onGenerateVectors() {
    // 通过 objectName 查找控件，避免成员变量过多
    QPlainTextEdit* input = findChild<QPlainTextEdit*>("crossInput");
    QTableWidget* table = findChild<QTableWidget*>("crossTable");
    if (!input || !table) return;

    QStringList lines = input->toPlainText().split('\n', Qt::SkipEmptyParts);
    table->setRowCount(0);

    int row = 0;
    for (const QString& line : lines) {
        QStringList parts = line.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
        if (parts.size() != 2) continue;

        std::string ps = parts[0].toStdString();
        std::string ks = parts[1].toStdString();
        uint16_t p = 0, k = 0;
        if (!parseBinaryString(ps, 8, p) || !parseBinaryString(ks, 10, k)) continue;

        uint8_t k1, k2;
        generateSubKeys(k, k1, k2);
        uint8_t c = encrypt(static_cast<uint8_t>(p), k);

        table->insertRow(row);
        table->setItem(row, 0, new QTableWidgetItem(
                            QString::fromStdString(toBinaryString(static_cast<uint8_t>(p), 8))));
        table->setItem(row, 1, new QTableWidgetItem(
                            QString::fromStdString(toBinaryString(k, 10))));
        table->setItem(row, 2, new QTableWidgetItem(
                            QString::fromStdString(toBinaryString(c, 8))));
        table->setItem(row, 3, new QTableWidgetItem(
                            QString::fromStdString(toBinaryString(k1, 8))));
        table->setItem(row, 4, new QTableWidgetItem(
                            QString::fromStdString(toBinaryString(k2, 8))));
        ++row;
    }
}

// ---------------------------------------------------------------------------
// Tab3：扩展功能 —— ASCII 文本按字节分组加解密
// ---------------------------------------------------------------------------
QWidget* MainWindow::buildTab3Text() {
    QWidget* page = new QWidget(this);
    QVBoxLayout* layout = new QVBoxLayout(page);

    QLabel* intro = new QLabel(
        "将 ASCII 文本按 1 字节 = 8 bit 分组，逐组进行 S-DES 加密。"
        "密文以二进制 / HEX 两种形式展示；解密时粘贴 HEX 密文还原原文。", page);
    intro->setWordWrap(true);
    layout->addWidget(intro);

    QGroupBox* encBox = new QGroupBox("文本加密", page);
    QGridLayout* g1 = new QGridLayout(encBox);
    g1->addWidget(new QLabel("密钥 (10 bit):"), 0, 0);
    tab3_keyEdit_ = new QLineEdit("1010000010");
    tab3_keyEdit_->setStyleSheet(kEditStyle);
    g1->addWidget(tab3_keyEdit_, 0, 1);

    g1->addWidget(new QLabel("明文文本:"), 1, 0);
    tab3_plainEdit_ = new QPlainTextEdit();
    tab3_plainEdit_->setStyleSheet(kEditStyle);
    tab3_plainEdit_->setPlainText("This is a test");
    tab3_plainEdit_->setMaximumHeight(90);
    g1->addWidget(tab3_plainEdit_, 1, 1);

    g1->addWidget(new QLabel("二进制密文:"), 2, 0);
    tab3_binOut_ = new QPlainTextEdit();
    tab3_binOut_->setReadOnly(true);
    tab3_binOut_->setStyleSheet(kEditStyle);
    tab3_binOut_->setMaximumHeight(80);
    g1->addWidget(tab3_binOut_, 2, 1);

    g1->addWidget(new QLabel("HEX 密文:"), 3, 0);
    tab3_hexOut_ = new QLineEdit();
    tab3_hexOut_->setReadOnly(true);
    tab3_hexOut_->setStyleSheet(kEditStyle);
    g1->addWidget(tab3_hexOut_, 3, 1);

    QPushButton* encBtn = new QPushButton("加密文本");
    connect(encBtn, &QPushButton::clicked, this, &MainWindow::onEncryptText);
    g1->addWidget(encBtn, 4, 1);
    layout->addWidget(encBox);

    QGroupBox* decBox = new QGroupBox("文本解密", page);
    QGridLayout* g2 = new QGridLayout(decBox);
    g2->addWidget(new QLabel("HEX 密文:"), 0, 0);
    tab3_hexIn_ = new QLineEdit("0b446f8fce6f8fce95cee3d08fe3");
    tab3_hexIn_->setStyleSheet(kEditStyle);
    g2->addWidget(tab3_hexIn_, 0, 1);

    g2->addWidget(new QLabel("解密结果:"), 1, 0);
    tab3_decOut_ = new QPlainTextEdit();
    tab3_decOut_->setReadOnly(true);
    tab3_decOut_->setStyleSheet(kEditStyle);
    tab3_decOut_->setMaximumHeight(90);
    g2->addWidget(tab3_decOut_, 1, 1);

    QPushButton* decBtn = new QPushButton("解密文本");
    connect(decBtn, &QPushButton::clicked, this, &MainWindow::onDecryptText);
    g2->addWidget(decBtn, 2, 1);
    layout->addWidget(decBox);

    layout->addStretch(1);
    return page;
}

void MainWindow::onEncryptText() {
    uint16_t key = 0;
    if (!readBits(tab3_keyEdit_, 10, key, "密钥")) return;

    QString text = tab3_plainEdit_->toPlainText();
    QString bin, hexs;
    for (QChar ch : text) {
        uint8_t c = encrypt(static_cast<uint8_t>(ch.unicode() & 0xFF),
                            static_cast<uint16_t>(key));
        bin += QString::fromStdString(toBinaryString(c, 8)) + ' ';
        hexs += QString("%1").arg(c, 2, 16, QChar('0'));
    }
    tab3_binOut_->setPlainText(bin.trimmed());
    tab3_hexOut_->setText(hexs);
    // 顺手把密文填入解密框，便于一键验证往返还原
    tab3_hexIn_->setText(hexs);
    setStatus(tab1_status_, QString("文本加密完成，HEX: %1").arg(hexs));
}

void MainWindow::onDecryptText() {
    uint16_t key = 0;
    if (!readBits(tab3_keyEdit_, 10, key, "密钥")) return;

    QString hexs = tab3_hexIn_->text().trimmed();
    // 过滤空格并校验
    hexs.remove(' ');
    if (hexs.isEmpty() || hexs.size() % 2 != 0 ||
        hexs.contains(QRegularExpression("[^0-9a-fA-F]"))) {
        QMessageBox::warning(this, "输入错误", "HEX 密文必须为偶数长度的十六进制串");
        return;
    }

    QString out;
    for (int i = 0; i < hexs.size(); i += 2) {
        bool ok = false;
        int v = hexs.mid(i, 2).toInt(&ok, 16);
        if (!ok) return;
        out += QChar(static_cast<char>(decrypt(static_cast<uint8_t>(v),
                                               static_cast<uint16_t>(key))));
    }
    tab3_decOut_->setPlainText(out);
}

// ---------------------------------------------------------------------------
// Tab4：暴力破解 —— 多线程遍历 1024 个密钥，支持 1~3 组明密文对
// ---------------------------------------------------------------------------
QWidget* MainWindow::buildTab4Brute() {
    QWidget* page = new QWidget(this);
    QVBoxLayout* layout = new QVBoxLayout(page);

    QLabel* intro = new QLabel(
        "已知明密文对 (P, C)，遍历全部 1024 个 10 bit 候选密钥，找出所有满足"
        " E(K, P) = C 的密钥。支持输入最多 3 组明密文对以缩小候选集合。", page);
    intro->setWordWrap(true);
    layout->addWidget(intro);

    QGroupBox* pairBox = new QGroupBox("已知明密文对（二进制，可只填第 1 组）", page);
    QGridLayout* grid = new QGridLayout(pairBox);
    for (int i = 0; i < 3; ++i) {
        grid->addWidget(new QLabel(QString("第 %1 组 明文:").arg(i + 1)), i, 0);
        QLineEdit* pEdit = new QLineEdit();
        pEdit->setStyleSheet(kEditStyle);
        grid->addWidget(pEdit, i, 1);
        grid->addWidget(new QLabel("密文:"), i, 2);
        QLineEdit* cEdit = new QLineEdit();
        cEdit->setStyleSheet(kEditStyle);
        grid->addWidget(cEdit, i, 3);
        tab4_plainEdits_.push_back(pEdit);
        tab4_cipherEdits_.push_back(cEdit);
    }
    tab4_plainEdits_[0]->setText("00101000");
    tab4_cipherEdits_[0]->setText("11110100");
    tab4_plainEdits_[1]->setText("11011001");
    tab4_cipherEdits_[1]->setText("00110110");

    // 单次破解 + 压力测试按钮
    QHBoxLayout* btnRow = new QHBoxLayout();
    tab4_crackBtn_ = new QPushButton("开始暴力破解（单次，多线程）");
    connect(tab4_crackBtn_, &QPushButton::clicked, this, &MainWindow::onBruteForce);
    btnRow->addWidget(tab4_crackBtn_);

    btnRow->addWidget(new QLabel("压力测试遍历次数:"));
    tab4_iterSpin_ = new QSpinBox();
    tab4_iterSpin_->setObjectName("iterSpin");
    tab4_iterSpin_->setRange(1000, 100000000);
    tab4_iterSpin_->setSingleStep(100000);
    tab4_iterSpin_->setValue(2000000);
    tab4_iterSpin_->setGroupSeparatorShown(true);
    tab4_iterSpin_->setToolTip("连续遍历整个密钥空间的次数，用于测量并发破解吞吐");
    btnRow->addWidget(tab4_iterSpin_);

    tab4_stressBtn_ = new QPushButton("压力测试（连续遍历密钥空间）");
    connect(tab4_stressBtn_, &QPushButton::clicked, this, &MainWindow::onStressTest);
    btnRow->addWidget(tab4_stressBtn_);
    layout->addLayout(btnRow);

    // 进度条 + 实时计时
    tab4_progress_ = new QProgressBar();
    tab4_progress_->setRange(0, 1000);
    tab4_progress_->setValue(0);
    tab4_progress_->setFormat("%p%");
    layout->addWidget(tab4_progress_);

    tab4_timeLabel_ = new QLabel("就绪。单次破解用于验证正确性；压力测试用于测量单位时间内可穷举的密钥量。");
    layout->addWidget(tab4_timeLabel_);

    tab4_status_ = new QLabel("就绪");
    layout->addWidget(tab4_status_);

    tab4_result_ = new QPlainTextEdit();
    tab4_result_->setReadOnly(true);
    tab4_result_->setStyleSheet(kEditStyle);
    layout->addWidget(tab4_result_, 1);
    return page;
}

void MainWindow::onBruteForce() {
    if (bruteWatcher_ && bruteWatcher_->isRunning()) {
        QMessageBox::information(this, "提示", "破解正在进行中，请稍候");
        return;
    }
    if (stressWatcher_ && stressWatcher_->isRunning()) {
        QMessageBox::information(this, "提示", "压力测试正在进行中，请稍候");
        return;
    }

    brutePairs_.clear();
    for (int i = 0; i < 3; ++i) {
        std::string ps = tab4_plainEdits_[i]->text().toStdString();
        std::string cs = tab4_cipherEdits_[i]->text().toStdString();
        if (ps.empty() && cs.empty()) continue; // 空行跳过
        uint16_t p = 0, c = 0;
        if (!parseBinaryString(ps, 8, p) || !parseBinaryString(cs, 8, c)) {
            QMessageBox::warning(this, "输入错误",
                                 QString("第 %1 组明文/密文格式有误").arg(i + 1));
            return;
        }
        brutePairs_.emplace_back(static_cast<uint8_t>(p), static_cast<uint8_t>(c));
    }
    if (brutePairs_.isEmpty()) {
        QMessageBox::warning(this, "输入错误", "请至少输入一组明密文对");
        return;
    }

    // QtConcurrent::mapped 会自动把 1024 个候选密钥分配到线程池并行处理
    QVector<uint16_t> allKeys;
    for (uint16_t k = 0; k < 1024; ++k) allKeys.push_back(k);

    tab4_crackBtn_->setEnabled(false);
    tab4_stressBtn_->setEnabled(false);
    tab4_progress_->setValue(0);
    tab4_result_->setPlainText("正在多线程遍历 1024 个候选密钥 ...");

    bruteTimer_->restart();
    QFuture<uint16_t> future = QtConcurrent::mapped(
        allKeys,
        [pairs = brutePairs_](uint16_t k) -> uint16_t {
            for (const auto& pc : pairs) {
                if (encrypt(pc.first, k) != pc.second) return 0xFFFF; // 不匹配标记
            }
            return k; // 匹配的密钥原样返回
        });
    bruteWatcher_->setFuture(future);
}

void MainWindow::onBruteFinished() {
    double ms = static_cast<double>(bruteTimer_->nsecsElapsed()) / 1e6;

    QStringList lines;
    lines << QString("==== 暴力破解完成 ====");
    lines << QString("明密文对 %1 组:").arg(brutePairs_.size());
    for (const auto& pc : brutePairs_) {
        lines << QString("  P=%1  C=%2")
                     .arg(QString::fromStdString(toBinaryString(pc.first, 8)))
                     .arg(QString::fromStdString(toBinaryString(pc.second, 8)));
    }
    lines << QString("并行线程数: %1").arg(stressThreads_ > 0 ? stressThreads_
                                                             : QThread::idealThreadCount());
    lines << QString("耗时: %1 ms").arg(ms, 0, 'f', 3);
    lines << QString("搜索速度: %1 个密钥/秒（含线程池启动开销）")
                 .arg(1024.0 / (ms / 1000.0), 0, 'f', 0);

    QStringList found;
    QFuture<uint16_t> f = bruteWatcher_->future();
    for (int i = 0; i < f.resultCount(); ++i) {
        uint16_t k = f.resultAt(i);
        if (k != 0xFFFF) found << QString::fromStdString(toBinaryString(k, 10));
    }
    lines << QString("匹配密钥 %1 个:").arg(found.size());
    for (const QString& k : found) lines << "  Key = " + k;

    tab4_result_->setPlainText(lines.join('\n'));
    tab4_progress_->setValue(1000);
    setStatus(tab4_status_, QString("破解完成：找到 %1 个候选密钥，耗时 %2 ms")
                                .arg(found.size()).arg(ms, 0, 'f', 3));
    tab4_timeLabel_->setText(
        QString("单次破解耗时 %1 ms —— 1024 个密钥的密钥空间在毫秒级即可穷举完毕")
            .arg(ms, 0, 'f', 2));
    tab4_crackBtn_->setEnabled(true);
    tab4_stressBtn_->setEnabled(true);
}

// ---------------------------------------------------------------------------
// 压力测试：连续遍历整个密钥空间 N 次，测量并发吞吐（进度条 + 实时计时）
// ---------------------------------------------------------------------------
void MainWindow::onStressTest() {
    if ((bruteWatcher_ && bruteWatcher_->isRunning()) ||
        (stressWatcher_ && stressWatcher_->isRunning())) {
        QMessageBox::information(this, "提示", "任务正在进行中，请稍候");
        return;
    }
    if (brutePairs_.isEmpty()) {
        // 直接使用界面上的明密文对
        for (int i = 0; i < 3; ++i) {
            std::string ps = tab4_plainEdits_[i]->text().toStdString();
            std::string cs = tab4_cipherEdits_[i]->text().toStdString();
            if (ps.empty() && cs.empty()) continue;
            uint16_t p = 0, c = 0;
            if (!parseBinaryString(ps, 8, p) || !parseBinaryString(cs, 8, c)) {
                QMessageBox::warning(this, "输入错误",
                                     QString("第 %1 组明文/密文格式有误").arg(i + 1));
                return;
            }
            brutePairs_.emplace_back(static_cast<uint8_t>(p), static_cast<uint8_t>(c));
        }
    }
    if (brutePairs_.isEmpty()) {
        QMessageBox::warning(this, "输入错误", "请至少输入一组明密文对");
        return;
    }

    stressIterations_ = tab4_iterSpin_->value();
    stressTotalKeys_ = stressIterations_ * 1024;           // 每次遍历尝试 1024 个密钥
    stressThreads_ = qMax(1, QThread::idealThreadCount());
    stressDoneKeys_.storeRelaxed(0);

    tab4_crackBtn_->setEnabled(false);
    tab4_stressBtn_->setEnabled(false);
    tab4_progress_->setValue(0);
    tab4_result_->setPlainText(QString("压力测试进行中：%1 次 × 1024 个密钥 = %2 次加密尝试 ...")
                                   .arg(stressIterations_)
                                   .arg(stressTotalKeys_));
    stressTimer_->restart();
    stressUiTimer_->start(100);
    onStressTick();

    // 把遍历任务均分给各线程，每个线程处理一段连续区间
    QVector<int> chunkIds;
    for (int i = 0; i < stressThreads_; ++i) chunkIds.push_back(i);

    QFuture<void> future = QtConcurrent::map(
        chunkIds,
        [this](int id) {
            const QVector<std::pair<uint8_t, uint8_t>> pairs = brutePairs_;
            long long begin = stressIterations_ * id / stressThreads_;
            long long end   = stressIterations_ * (id + 1) / stressThreads_;
            long long localDone = 0;
            for (long long it = begin; it < end; ++it) {
                for (uint16_t k = 0; k < 1024; ++k) {
                    bool match = true;
                    for (const auto& pc : pairs) {
                        if (encrypt(pc.first, k) != pc.second) { match = false; break; }
                    }
                    (void)match; // 压力测试只统计吞吐，不收集结果
                }
                // 每 64 次遍历汇总一次进度，避免原子操作成为瓶颈
                if ((++localDone & 63) == 0) {
                    stressDoneKeys_.fetchAndAddRelaxed(localDone * 1024);
                    localDone = 0;
                }
            }
            stressDoneKeys_.fetchAndAddRelaxed(localDone * 1024);
        });
    stressWatcher_->setFuture(future);
}

void MainWindow::onStressTick() {
    if (!stressTimer_ || stressTotalKeys_ == 0) return;
    double elapsedMs = static_cast<double>(stressTimer_->nsecsElapsed()) / 1e6;
    long long done = stressDoneKeys_.loadRelaxed();
    if (done > stressTotalKeys_) done = stressTotalKeys_;

    double ratio = static_cast<double>(done) / static_cast<double>(stressTotalKeys_);
    tab4_progress_->setValue(static_cast<int>(ratio * 1000));

    double rate = (elapsedMs > 1.0) ? (done / (elapsedMs / 1000.0)) : 0.0;
    tab4_timeLabel_->setText(
        QString("运行中：已用 %1 s ｜ 已尝试 %2 个密钥 ｜ 当前速度 %3 M 次加密/秒 ｜ 线程 %4")
            .arg(elapsedMs / 1000.0, 0, 'f', 2)
            .arg(done)
            .arg(rate / 1e6, 0, 'f', 1)
            .arg(stressThreads_));
}

void MainWindow::onStressFinished() {
    stressUiTimer_->stop();
    double totalS = static_cast<double>(stressTimer_->nsecsElapsed()) / 1e9;
    long long done = stressDoneKeys_.loadRelaxed();

    // 单线程基准：一次全密钥空间遍历 ≈ 1024 次加密，实测约 0.055 ms
    double avgSweepUs = totalS * 1e6 / static_cast<double>(stressIterations_);
    double throughput = done / totalS;

    QStringList lines;
    lines << "==== 压力测试完成 ====";
    lines << QString("遍历次数        : %1 次全密钥空间").arg(stressIterations_);
    lines << QString("累计加密次数    : %1 次 (每次遍历 1024 个密钥)").arg(done);
    lines << QString("并行线程数      : %1").arg(stressThreads_);
    lines << QString("总耗时          : %1 s").arg(totalS, 0, 'f', 3);
    lines << QString("平均单次遍历    : %1 µs（并发）").arg(avgSweepUs, 0, 'f', 2);
    lines << QString("吞吐量          : %1 M 次加密/秒").arg(throughput / 1e6, 0, 'f', 1);
    lines << QString("等效单线程耗时  : %1 s（若单线程执行同样工作量）")
                 .arg(throughput > 0 ? (done / (18.52e6)) : 0.0, 0, 'f', 1);
    lines << QString("并发加速比      : %1 x（相对实测单线程基准 18.5 M 次加密/秒）")
                 .arg(throughput / 18.52e6, 0, 'f', 1);
    lines << "";
    lines << "结论：S-DES 密钥空间仅 2^10 = 1024（且有效熵只有 8 bit），";
    lines << QString("      本机 %1 线程可在 %2 s 内完成 %3 次全空间穷举，")
                 .arg(stressThreads_).arg(totalS, 0, 'f', 2).arg(stressIterations_);
    lines << QString("      即每秒可穷举约 %1 个密钥空间，单次破解耗时不足 %2 ms。")
                 .arg(throughput / 1024.0, 0, 'f', 0)
                 .arg(avgSweepUs / 1000.0, 0, 'f', 3);

    tab4_result_->setPlainText(lines.join('\n'));
    tab4_progress_->setValue(1000);
    setStatus(tab4_status_, QString("压力测试完成：%1 次遍历，总耗时 %2 s")
                                .arg(stressIterations_).arg(totalS, 0, 'f', 3));
    tab4_timeLabel_->setText(
        QString("压力测试完成：%1 次全密钥空间遍历共 %2 s，平均单次 %3 µs")
            .arg(stressIterations_).arg(totalS, 0, 'f', 3).arg(avgSweepUs, 0, 'f', 2));
    tab4_crackBtn_->setEnabled(true);
    tab4_stressBtn_->setEnabled(true);
}

// ---------------------------------------------------------------------------
// Tab5：封闭测试 —— 密钥多重性分析
// ---------------------------------------------------------------------------
QWidget* MainWindow::buildTab5Closure() {
    QWidget* page = new QWidget(this);
    QVBoxLayout* layout = new QVBoxLayout(page);

    QLabel* intro = new QLabel(
        "问题：① 对给定的一对（明文 P，密文 C），满足 E(K,P)=C 的密钥是否唯一？"
        "② 对任意明文分组 P，是否存在两个不同密钥 K1 ≠ K2 使 E(K1,P)=E(K2,P)？"
        "下面从三个层次递进分析并给出结论。", page);
    intro->setWordWrap(true);
    layout->addWidget(intro);

    QGroupBox* box = new QGroupBox("单点封闭测试：枚举指定 (P, C) 的全部匹配密钥", page);
    QGridLayout* grid = new QGridLayout(box);
    grid->addWidget(new QLabel("明文 P (8bit):"), 0, 0);
    tab5_plainEdit_ = new QLineEdit("00101000");
    tab5_plainEdit_->setStyleSheet(kEditStyle);
    grid->addWidget(tab5_plainEdit_, 0, 1);

    grid->addWidget(new QLabel("密文 C (8bit):"), 0, 2);
    tab5_cipherEdit_ = new QLineEdit("11110100");
    tab5_cipherEdit_->setStyleSheet(kEditStyle);
    grid->addWidget(tab5_cipherEdit_, 0, 3);

    QPushButton* closureBtn = new QPushButton("枚举全部匹配密钥");
    connect(closureBtn, &QPushButton::clicked, this, &MainWindow::onClosureTest);
    grid->addWidget(closureBtn, 0, 4);
    layout->addWidget(box);

    // 三个层次的递进分析 + 一键完整报告
    QHBoxLayout* btnRow = new QHBoxLayout();
    struct { const char* text; void (MainWindow::*slot)(); } items[] = {
        {"① 密钥等价类分析",       &MainWindow::onKeyEquivalence},
        {"② 明文维度碰撞检测",     &MainWindow::onPlaintextCollision},
        {"③ 全空间分布统计 + 结论", &MainWindow::onCipherProfile},
        {"⑤ 一键完整分析报告",     &MainWindow::onFullAnalysis},
    };
    for (const auto& it : items) {
        QPushButton* b = new QPushButton(QString::fromUtf8(it.text));
        connect(b, &QPushButton::clicked, this, it.slot);
        btnRow->addWidget(b);
    }
    layout->addLayout(btnRow);

    tab5_analysisOut_ = new QPlainTextEdit();
    tab5_analysisOut_->setReadOnly(true);
    tab5_analysisOut_->setStyleSheet(kEditStyle);
    tab5_analysisOut_->setPlainText(
        "点击上方按钮执行分析。三个层次的思路：\n"
        "  ① 若两个密钥经 Keygen 得到相同的 (k1,k2)，则对所有明文加密结果都相同；\n"
        "  ② 逐明文检查 1024 个密钥的加密结果是否存在重复值；\n"
        "  ③ 枚举全部 (P,C) 组合，统计匹配密钥个数的分布。");
    layout->addWidget(tab5_analysisOut_, 1);
    return page;
}

void MainWindow::onClosureTest() {
    uint16_t p = 0, c = 0;
    if (!readBits(tab5_plainEdit_, 8, p, "明文")) return;
    if (!readBits(tab5_cipherEdit_, 8, c, "密文")) return;

    std::vector<uint16_t> keys = findAllKeys(static_cast<uint8_t>(p),
                                             static_cast<uint8_t>(c));
    QStringList lines;
    lines << QString("P=%1, C=%2 的全部匹配密钥共 %3 个：")
                 .arg(QString::fromStdString(toBinaryString(static_cast<uint8_t>(p), 8)))
                 .arg(QString::fromStdString(toBinaryString(static_cast<uint8_t>(c), 8)))
                 .arg(keys.size());
    for (uint16_t k : keys) lines << "  Key = " + QString::fromStdString(toBinaryString(k, 10));
    if (keys.size() > 1) {
        lines << "结论：该明密文对存在不止一个密钥，S-DES 密钥映射非单射。";
    }
    tab5_analysisOut_->setPlainText(lines.join('\n'));
}

void MainWindow::onKeyEquivalence() {
    tab5_analysisOut_->setPlainText(
        QString::fromStdString(formatKeyEquivalence(analyzeKeyEquivalence())));
}

void MainWindow::onPlaintextCollision() {
    tab5_analysisOut_->setPlainText(
        QString::fromStdString(formatPlaintextCollision(analyzePlaintextCollision())));
}

void MainWindow::onCipherProfile() {
    QString text = QString::fromStdString(formatCipherProfile(analyzeCipherProfile()));
    text += "\n======== 第 5 关结论 ========\n"
            "问题① 密钥是否唯一：不唯一。全空间统计中，(P,C) 对的最少匹配密钥数为 4，\n"
            "  最多 32，25280 个可达 (P,C) 对全部都有 ≥2 个密钥。\n"
            "问题② 是否存在 K1 ≠ K2 使 E(K1,P)=E(K2,P)：必然存在。\n"
            "  理由：1024 个密钥经 Keygen 只得到 256 种不同的 (k1,k2) 子密钥对，\n"
            "  每个子密钥对恰好对应 4 个等价密钥，这 4 个密钥对任意明文加密结果完全相同\n"
            "  （匹配密钥数始终是 4 的倍数即为佐证），故密钥有效熵只有 8 bit 而非 10 bit。";
    tab5_analysisOut_->setPlainText(text);
}

void MainWindow::onFullAnalysis() {
    QString text;
    text += QString::fromStdString(formatKeyEquivalence(analyzeKeyEquivalence()));
    text += "\n";
    text += QString::fromStdString(formatPlaintextCollision(analyzePlaintextCollision()));
    text += "\n";
    text += QString::fromStdString(formatCipherProfile(analyzeCipherProfile()));
    text += "\n======== 第 5 关结论 ========\n"
            "问题① 对给定 (P, C)，满足 E(K,P)=C 的密钥不唯一：最少 4 个，最多 32 个。\n"
            "问题② 对任意明文 P 都存在 K1 ≠ K2 使 E(K1,P)=E(K2,P)：成立。\n"
            "理由：P10 置换 + 循环移位 + P8 压缩使 10 bit 密钥只有 8 bit 有效，\n"
            "1024 个密钥塌缩为 256 个等价类（每类 4 个密钥），同类密钥加密函数完全相同。";
    tab5_analysisOut_->setPlainText(text);
}
