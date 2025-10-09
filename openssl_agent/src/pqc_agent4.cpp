#include "pqc_agent.h"
#include "ui_pqc_agent.h"

#include <QFileDialog>
#include <QProcess>
#include <QDirIterator>
#include <QMessageBox>
#include <QDateTime>
#include <QFile>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QDir>
#include <QTextStream>

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

    performScan(selectedFolder);
}

void PQC_Agent::performScan(const QString &folder)
{
    ui->outputText->clear();
    ui->labelStatus->setText("🔍 Scanning...");
    ui->progressBar->setValue(0);
    progressValue = 0;
    progressTimer->start(100);

    // Get OpenSSL algorithms
    QProcess process;
    process.start("openssl", {"list", "-public-key-algorithms"});
    process.waitForFinished();
    QString algoList = process.readAllStandardOutput();
    QStringList detectedAlgorithms = algoList.split('\n', Qt::SkipEmptyParts);

    QStringList results;
    results << "Detected Algorithms from OpenSSL:";
    results.append(detectedAlgorithms);

    ui->outputText->appendPlainText(results.join('\n'));

    // Scan files in folder
    QDirIterator it(folder, QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        it.next();
        ui->outputText->appendPlainText("Scanning file: " + it.filePath());
        results << "File: " + it.filePath();
    }

    ui->outputText->appendPlainText("\n✅ Scan Completed!");
    ui->labelStatus->setText("✅ Done!");
    ui->progressBar->setValue(100);
    progressTimer->stop();

    // Save to log files
    saveResultsToFiles(results);
}

void PQC_Agent::saveResultsToFiles(const QStringList &results)
{
    QString logDirPath = "/var/log/pqc_agent_scans";
    QDir().mkpath(logDirPath);

    QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss");
    QString jsonPath = logDirPath + "/scan_" + timestamp + ".json";
    QString csvPath  = logDirPath + "/scan_" + timestamp + ".csv";

    // JSON
    QJsonArray jsonArray;
    for (const QString &line : results)
        jsonArray.append(line);
    QJsonDocument doc(jsonArray);
    QFile jsonFile(jsonPath);
    if (jsonFile.open(QIODevice::WriteOnly))
        jsonFile.write(doc.toJson());

    // CSV
    QFile csvFile(csvPath);
    if (csvFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&csvFile);
        for (const QString &line : results){
	    QString safeLine =line;
	    safeLine.replace("\"","\"\"");
            out << "\"" << safeLine << "\"\n";
	}
    }

    ui->outputText->appendPlainText(
        QString("\n📄 Results saved:\n%1\n%2").arg(jsonPath, csvPath)
    );
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

void PQC_Agent::runHeadlessScan(const QString &folder)
{
    performScan(folder);
}
