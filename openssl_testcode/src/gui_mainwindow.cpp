#include "gui_mainwindow.h"
#include "ui_gui_mainwindow.h"
#include <QLibrary>
#include <QPlainTextEdit>
#include <QTextCursor>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(ui->btnClassical, &QPushButton::clicked, this, &MainWindow::onClassical);
    connect(ui->btnPQC, &QPushButton::clicked, this, &MainWindow::onPQC);
    connect(ui->btnKaz, &QPushButton::clicked, this, &MainWindow::onKaz);
    connect(ui->btnHybrid, &QPushButton::clicked, this, &MainWindow::onHybrid);
}

MainWindow::~MainWindow() { delete ui; }

void MainWindow::callCryptoFunc(const QString &funcName)
{
    QLibrary lib("./lib/libcryptoapi.so");
    if (!lib.load()) {
        ui->outputText->append("❌ Failed to load libcryptoapi.so");
        return;
    }

    typedef void (*CryptoFunc)();
    CryptoFunc fn = (CryptoFunc)lib.resolve(funcName.toUtf8().constData());
    if (!fn) {
        ui->outputText->append("⚠ Function " + funcName + " not found.");
        lib.unload();
        return;
    }

    ui->outputText->append("▶ Running " + funcName + "() ...");

    fn();

    ui->outputText->append("✅ Done with " + funcName + "()");
    ui->outputText->append("");
    ui->outputText->moveCursor(QTextCursor::End);

    lib.unload();
}

void MainWindow::onClassical() { callCryptoFunc("classical"); }
void MainWindow::onPQC()       { callCryptoFunc("pqc"); }
void MainWindow::onKaz()       { callCryptoFunc("kaz"); }
void MainWindow::onHybrid()    { callCryptoFunc("hybrid"); }
