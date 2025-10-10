#include "pqc_agent.h"
#include "ui_pqc_agent.h"
#include <QFileDialog>
#include <QDirIterator>
#include <QProcess>
#include <QMessageBox>
#include <QTimer>
#include <QTextStream>

PQC_Agent::PQC_Agent(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::PQC_Agent)
    , progressValue(0)
{
    ui->setupUi(this);

    // Connect buttons
    connect(ui->btnSelect, &QPushButton::clicked, this, &PQC_Agent::selectFolder);
    connect(ui->btnScan, &QPushButton::clicked, this, &PQC_Agent::startScan);

    // Timer for smooth progress bar animation
    progressTimer = new QTimer(this);
    connect(progressTimer, &QTimer::timeout, this, &PQC_Agent::updateProgress);
}

PQC_Agent::~PQC_Agent()
{
    delete ui;
}

void PQC_Agent::selectFolder()
{
    QString dir = QFileDialog::getExistingDirectory(this, "Select Folder to Scan", QDir::homePath());
    if (!dir.isEmpty()) {
        selectedFolder = dir;
        ui->labelStatus->setText("📁 Selected: " + dir);
    }
}

void PQC_Agent::startScan()
{
    if (selectedFolder.isEmpty()) {
        QMessageBox::warning(this, "Warning", "Please select a folder first!");
        return;
    }

    ui->outputText->clear();
    ui->labelStatus->setText("🔍 Scanning...");
    ui->progressBar->setValue(0);
    progressValue = 0;
    progressTimer->start(100);

    // Collect files recursively
    scannedFiles.clear();
    QDirIterator it(selectedFolder, QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        scannedFiles << it.next();
    }

    ui->outputText->appendPlainText(QString("Found %1 files to scan.\n").arg(scannedFiles.size()));

    currentFileIndex = 0;
    scanNextFile();
}

void PQC_Agent::scanNextFile()
{
    if (currentFileIndex >= scannedFiles.size()) {
        progressTimer->stop();
        ui->labelStatus->setText("✅ Scan Completed!");
        ui->progressBar->setValue(100);
        ui->outputText->appendPlainText("\n✅ Scan completed successfully.\n");
        return;
    }

    QString filePath = scannedFiles[currentFileIndex];
    QFile file(filePath);
    QStringList detectedAlgos;

    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QString content = file.readAll();
        file.close();

        // Look for common PQC or crypto-related algorithm keywords
        QStringList patterns = {
            "RSA", "DSA", "ECDSA", "ED25519", "KYBER", "MLDSA", "DILITHIUM", "FALCON",
            "BIKE", "SPHINCS", "AES", "CHACHA", "SHA", "SHA3", "BLAKE", "MD5"
        };

        for (const QString &algo : patterns) {
            if (content.contains(algo, Qt::CaseInsensitive)) {
                detectedAlgos << algo;
            }
        }
    }

    if (!detectedAlgos.isEmpty()) {
        ui->outputText->appendPlainText(QString("[%1]  🔹 %2")
            .arg(filePath, detectedAlgos.join(", ")));
    }

    currentFileIndex++;
    updateProgress();
    QTimer::singleShot(30, this, &PQC_Agent::scanNextFile);
}

void PQC_Agent::updateProgress()
{
    if (scannedFiles.isEmpty()) return;

    progressValue = (currentFileIndex * 100) / scannedFiles.size();
    ui->progressBar->setValue(progressValue);
}
