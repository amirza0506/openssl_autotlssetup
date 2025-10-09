#include "pqc_gui.h"
#include "ui_pqc_gui.h"
#include <QMessageBox>
#include <QTimer>
#include <QThread>

PQCGui::PQCGui(QWidget *parent)
    : QMainWindow(parent),
      ui(new Ui::PQCGui),
      manager(new PQCManager(this))
{
    ui->setupUi(this);

    // Connect Run button
    connect(ui->runButton, &QPushButton::clicked, this, &PQCGui::onRunClicked);
    ui->progressBar->setValue(0);
    ui->logOutput->appendPlainText("✅ PQC GUI Ready!");
}

PQCGui::~PQCGui()
{
    delete ui;
    delete manager;
}

void PQCGui::onRunClicked()
{
    QString role = ui->roleCombo->currentText();
    QString algo = ui->algoCombo->currentText();

    ui->logOutput->appendPlainText("▶ Selected Role: " + role);
    ui->logOutput->appendPlainText("▶ Algorithm: " + algo);
    ui->progressBar->setValue(10);

    // Simulate processing delay with interactive loading
    QTimer::singleShot(500, [this, role, algo]() {
        ui->logOutput->appendPlainText("⏳ Running " + role + " setup using " + algo + " ...");
        ui->progressBar->setValue(50);

        // Example — call PQCManager logic
        manager->runRole(role, algo);

        QTimer::singleShot(1000, [this]() {
            ui->logOutput->appendPlainText("✅ Operation completed successfully!");
            ui->progressBar->setValue(100);
            QMessageBox::information(this, "Done", "All tasks completed successfully 🎉");
        });
    });
}
