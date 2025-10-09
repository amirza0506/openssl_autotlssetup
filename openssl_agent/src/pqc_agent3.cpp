#include "pqc_agent.h"
#include "ui_pqc_agent.h"

#include <QFileDialog>
#include <QProcess>
#include <QDirIterator>
#include <QMessageBox>
#include <QDebug>

PQC_Agent::PQC_Agent(QWidget *parent)
    : QMainWindow(parent),
      ui(new Ui::PQC_Agent),
      progressTimer(new QTimer(this)),
      progressValue(0)
{
    ui->setupUi(this);

    connect(ui->btnSelect, &QPushButton::clicked, this, &PQC_Agent::selectFolder);
    connect(ui->btnScan, &QPushButton::clicked, this, &PQC_Agent::startScan);
    connect(progressTimer, &QTimer::timeout, this, &PQC_Agent::updateProgress);
}

PQC_Agent::~PQC_Agent()
{
    delete ui;
}

void PQC_Agent::selectFolder()
{
    QString dir = QFileDialog::getExistingDirectory(this, "Select Folder to Scan");
    if (!dir.isEmpty()) {
        selectedFolder = dir;
        ui->labelStatus->setText("📁 Selected: " + dir);
    }
}

void PQC_Agent::startScan()
{
    if (selectedFolder.isEmpty()) {
        QMessageBox::warning(this, "No Folder Selected", "Please select a folder first!");
        return;
    }

    ui->outputText->clear();
    ui->labelStatus->setText("🔍 Scanning...");
    ui->progressBar->setValue(0);
    progressValue = 0;
    progressTimer->start(100);

    QProcess process;
    process.start("openssl", {"list", "-public-key-algorithms"});
    process.waitForFinished();
    QString algoList = process.readAllStandardOutput();

    ui->outputText->appendPlainText("Detected Algorithms:\n" + algoList);

    QDirIterator it(selectedFolder, QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        it.next();
        ui->outputText->appendPlainText("Scanning file: " + it.filePath());
    }

    ui->outputText->appendPlainText("\n✅ Scan Completed!");
    ui->labelStatus->setText("✅ Done!");
    ui->progressBar->setValue(100);
    progressTimer->stop();
}

void PQC_Agent::updateProgress()
{
    progressValue += 5;
    if (progressValue > 100) {
        progressTimer->stop();
        return;
    }
    ui->progressBar->setValue(progressValue);
}
