#include "gui_mainwindow.h"
#include "ui_gui_mainwindow.h"
#include "gui_mainwindow.h"
#include <QMessageBox>
#include <dlfcn.h>
#include <iostream>

typedef void (*voidFunc)();

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);

    connect(ui->btnGenerate, &QPushButton::clicked, this, &MainWindow::onGenerate);
    connect(ui->btnSign, &QPushButton::clicked, this, &MainWindow::onSign);
    connect(ui->btnVerify, &QPushButton::clicked, this, &MainWindow::onVerify);
}

MainWindow::~MainWindow() { delete ui; }

void MainWindow::onGenerate() {
    void *handle = dlopen("./lib/libcryptoapi.so", RTLD_LAZY);
    if (!handle) {
        ui->txtOutput->appendPlainText("❌ Failed to load libcryptoapi.so");
        return;
    }
    voidFunc func = (voidFunc)dlsym(handle, "classical");
    if (func) {
        func();
        ui->txtOutput->appendPlainText("✅ RSA/Classic key generated.");
    } else {
        ui->txtOutput->appendPlainText("⚠️ Function 'classical' not found.");
    }
    dlclose(handle);
}

void MainWindow::onSign() {
    ui->txtOutput->appendPlainText("🖋 Signing message (placeholder for now)...");
}

void MainWindow::onVerify() {
    ui->txtOutput->appendPlainText("🔍 Verifying signature (placeholder for now)...");
}
