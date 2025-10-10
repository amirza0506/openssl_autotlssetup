#include "pqc_agent.h"
#include "ui_pqc_agent.h"
#include <QFileDialog>
#include <QDirIterator>
#include <QMessageBox>
#include <QProcess>
#include <QTextStream>
#include <QDateTime>
#include <QCoreApplication>

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
    QString dir = QFileDialog::getExistingDirectory(this, "Select Directory to Scan");
    if (!dir.isEmpty()) {
        selectedFolder = dir;
        ui->labelStatus->setText("📁 Selected: " + dir);
    }
}

void PQC_Agent::startScan()
{
    if (selectedFolder.isEmpty()) {
        QMessageBox::warning(this, "No Folder Selected", "Please select a folder to scan first.");
        return;
    }

    ui->outputText->clear();
    ui->labelStatus->setText("🔍 Scanning...");
    ui->progressBar->setValue(0);

    progressValue = 0;
    progressTimer->start(100);

    QStringList results;

    // Step 1: List OpenSSL algorithms
    QProcess process;
    process.start("openssl", QStringList() << "list" << "-cipher-algorithms");
    process.waitForFinished();
    QString algoList = process.readAllStandardOutput().trimmed();

    ui->outputText->appendPlainText("Detected Algorithms from OpenSSL:\n" + algoList + "\n");
    results << "=== Detected Algorithms from OpenSSL ===";
    results << algoList.split('\n');

    // Step 2: Scan crypto-related files
    QStringList cryptoExtensions = {".pem", ".crt", ".cer", ".csr", ".key", ".p12", ".so", ".dll", ".lib", ".a"};
    QDirIterator it(selectedFolder, QDir::Files, QDirIterator::Subdirectories);

    int totalCount = 0;
    while (it.hasNext()) {
        it.next();
        QFileInfo file = it.fileInfo();

        QString ext = file.suffix().toLower();
        if (!cryptoExtensions.contains("." + ext))
            continue;

        totalCount++;
        QString filePath = file.absoluteFilePath();
        results << "Found crypto-related file: " + filePath;
        ui->outputText->appendPlainText("🔎 Found crypto file: " + file.fileName());
        QCoreApplication::processEvents();
    }

    if (totalCount == 0) {
        ui->outputText->appendPlainText("\n⚠️ No crypto-related files found in this directory.");
    } else {
        ui->outputText->appendPlainText("\n✅ Scan completed! Found " + QString::number(totalCount) + " crypto-related files.");
    }

    ui->labelStatus->setText("✅ Done!");
    ui->progressBar->setValue(100);
    progressTimer->stop();

    // Step 3: Save results automatically
    ui->outputText->appendPlainText("\n💾 Exporting results automatically...");
    saveResultsToFiles(results);
}

void PQC_Agent::updateProgress()
{
    progressValue += 5;
    if (progressValue > 100)
        progressTimer->stop();
    ui->progressBar->setValue(progressValue);
}

void PQC_Agent::saveResultsToFiles(const QStringList &results)
{
    QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss");
    QString basePath = QDir::homePath() + "/openssl_agent/pqc_scan_results_" + timestamp;

    QFile txtFile(basePath + ".txt");
    if (txtFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&txtFile);
        for (const QString &line : results)
            out << line << "\n";
        txtFile.close();
    }

    QFile csvFile(basePath + ".csv");
    if (csvFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&csvFile);
        for (const QString &line : results)
            out << "\"" << QString(line).replace("\"", "\"\"") << "\"\n";
        csvFile.close();
    }

    ui->outputText->appendPlainText("📂 Results saved to:\n" + basePath + ".txt\n" + basePath + ".csv");
}
