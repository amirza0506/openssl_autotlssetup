#include "pqc_agent.h"
#include "ui_pqc_agent.h"

#include <QFileDialog>
#include <QFile>
#include <QTextStream>
#include <QTableWidgetItem>

PQC_Agent::PQC_Agent(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::PQC_Agent) {
    ui->setupUi(this);
    ui->tableWidget->setColumnCount(3);
    ui->tableWidget->setHorizontalHeaderLabels(QStringList() << "File" << "Algorithm" << "Key Size");
}

PQC_Agent::~PQC_Agent() {
    delete ui;
}

void PQC_Agent::on_scanButton_clicked() {
    QString filePath = QFileDialog::getOpenFileName(this, "Select File");
    if (!filePath.isEmpty()) {
        scanFile(filePath);
    }
}

void PQC_Agent::scanFile(const QString &filePath) {
    // Dummy data for demonstration
    QString algo = "ML-DSA";
    QString keySize = "2048";

    int row = ui->tableWidget->rowCount();
    ui->tableWidget->insertRow(row);
    ui->tableWidget->setItem(row, 0, new QTableWidgetItem(filePath));
    ui->tableWidget->setItem(row, 1, new QTableWidgetItem(algo));
    ui->tableWidget->setItem(row, 2, new QTableWidgetItem(keySize));
}

void PQC_Agent::on_exportButton_clicked() {
    QString csvPath = QFileDialog::getSaveFileName(this, "Export CSV", "", "CSV Files (*.csv)");
    QString txtPath = QFileDialog::getSaveFileName(this, "Export Text", "", "Text Files (*.txt)");

    if (!csvPath.isEmpty()) {
        QFile csvFile(csvPath);
        if (csvFile.open(QIODevice::WriteOnly)) {
            QTextStream out(&csvFile);
            for (int i = 0; i < ui->tableWidget->rowCount(); ++i) {
                QStringList row;
                for (int j = 0; j < ui->tableWidget->columnCount(); ++j)
                    row << ui->tableWidget->item(i, j)->text();
                out << row.join(",") << "\n";
            }
        }
    }

    if (!txtPath.isEmpty()) {
        QFile txtFile(txtPath);
        if (txtFile.open(QIODevice::WriteOnly)) {
            QTextStream out(&txtFile);
            for (int i = 0; i < ui->tableWidget->rowCount(); ++i)
                out << ui->tableWidget->item(i, 0)->text() << " - "
                    << ui->tableWidget->item(i, 1)->text() << " "
                    << ui->tableWidget->item(i, 2)->text() << "\n";
        }
    }
}
