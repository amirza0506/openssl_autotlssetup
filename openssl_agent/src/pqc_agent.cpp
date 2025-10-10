#include "pqc_agent.h"
#include "ui_pqc_agent.h"
#include <QFileDialog>
#include <QDirIterator>
#include <QMessageBox>
#include <QDateTime>
#include <QTextStream>
#include <QJsonDocument>
#include <QJsonObject>

PQC_Agent::PQC_Agent(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::PQC_Agent)
    , currentFileIndex(0)
    , progressValue(0)
{
    ui->setupUi(this);

    connect(ui->btnSelect, &QPushButton::clicked, this, &PQC_Agent::selectFolder);
    connect(ui->btnScan, &QPushButton::clicked, this, &PQC_Agent::startScan);
    connect(ui->btnExport, &QPushButton::clicked, this, &PQC_Agent::exportResults);

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
    scanResults = QJsonArray();

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

        QStringList patterns = {
            "RSA","DSA","ECDSA","ED25519","KYBER","MLDSA",
            "DILITHIUM","FALCON","BIKE","SPHINCS","AES",
            "CHACHA","SHA","SHA3","BLAKE","MD5"
        };
        for (const QString &algo : patterns) {
            if (content.contains(algo, Qt::CaseInsensitive))
                detectedAlgos << algo;
        }
    }

    if (!detectedAlgos.isEmpty()) {
        ui->outputText->appendPlainText(QString("[%1]  🔹 %2")
            .arg(filePath, detectedAlgos.join(", ")));

        QJsonObject entry;
        entry["file"] = filePath;
        QJsonArray algos;
        for (const QString &a : detectedAlgos) algos.append(a);
        entry["algorithms"] = algos;
        scanResults.append(entry);
    }

    currentFileIndex++;
    updateProgress();
    QTimer::singleShot(15, this, &PQC_Agent::scanNextFile);
}

void PQC_Agent::updateProgress()
{
    if (scannedFiles.isEmpty()) return;
    progressValue = (currentFileIndex * 100) / scannedFiles.size();
    ui->progressBar->setValue(progressValue);
}

void PQC_Agent::exportResults()
{
    if (scanResults.isEmpty()) {
        ui->outputText->appendPlainText("No algorithms detected. Nothing to export.");
        return;
    }

    QString exportDir = selectedFolder + "/pqc_scan_results";
    QDir().mkpath(exportDir);

    QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss");
    QString jsonPath = exportDir + QString("/results_%1.json").arg(timestamp);
    QString csvPath  = exportDir + QString("/results_%1.csv").arg(timestamp);

    // JSON output
    QFile jsonFile(jsonPath);
    if (jsonFile.open(QIODevice::WriteOnly)) {
        QJsonDocument doc(scanResults);
        jsonFile.write(doc.toJson(QJsonDocument::Indented));
        jsonFile.close();
        ui->outputText->appendPlainText("📄 JSON saved to: " + jsonPath);
    }

    // CSV output
    QFile csvFile(csvPath);
    if (csvFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&csvFile);
        out << "File,Algorithms\n";
        for (const QJsonValue &val : scanResults) {
            QJsonObject obj = val.toObject();
            QStringList algoList;
            for (const QJsonValue &algo : obj["algorithms"].toArray())
                algoList << algo.toString();
            out << "\"" << obj["file"].toString() << "\",\""
                << algoList.join(", ") << "\"\n";
        }
        csvFile.close();
        ui->outputText->appendPlainText("📊 CSV saved to: " + csvPath);
    }

    ui->outputText->appendPlainText("\n📁 Results exported to " + exportDir);
}
