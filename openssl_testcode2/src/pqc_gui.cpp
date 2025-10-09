#include "pqc_gui.h"
#include "ui_pqc_gui.h"
#include "pqc_manager.h"

#include <QMessageBox>
#include <QTimer>
#include <QProcess>

PQC_GUI::PQC_GUI(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::PQC_GUI)
    , manager(new PQCManager(this))
{
    ui->setupUi(this);
    ui->progress_bar->setValue(0);

    selectedRole = "None";

    // Role buttons
    connect(ui->btn_ca, &QPushButton::clicked, this, [this]() {
        selectedRole = "CA";
        ui->log_output->append("<font color='yellow'>[INFO]</font> Role selected: CA");
    });
    connect(ui->btn_server, &QPushButton::clicked, this, [this]() {
        selectedRole = "Server";
        ui->log_output->append("<font color='yellow'>[INFO]</font> Role selected: Server");
    });
    connect(ui->btn_client, &QPushButton::clicked, this, [this]() {
        selectedRole = "Client";
        ui->log_output->append("<font color='yellow'>[INFO]</font> Role selected: Client");
    });

    // Algorithm refresh
    connect(ui->btn_refresh, &QPushButton::clicked, this, &PQC_GUI::refreshAlgorithms);
    refreshAlgorithms();

    // Run Task
    connect(ui->btn_run, &QPushButton::clicked, this, &PQC_GUI::runTask);
}

void PQC_GUI::refreshAlgorithms()
{
    ui->combo_algo->clear();

    QProcess process;
    process.start("bash", QStringList() << "-c" << "openssl list -public-key-algorithms | grep ML- || echo 'ML-DSA-44\nML-KEM-768\nECDSA\nRSA'");
    process.waitForFinished();

    QString output = process.readAllStandardOutput();
    QStringList algos = output.split("\n", Qt::SkipEmptyParts);
    ui->combo_algo->addItems(algos);

    ui->log_output->append("<font color='lime'>[OK]</font> Algorithm list refreshed.");
}

void PQC_GUI::runTask()
{
    if (selectedRole == "None") {
        QMessageBox::warning(this, "Warning", "Please select a role first!");
        return;
    }

    QString algo = ui->combo_algo->currentText();
    ui->log_output->append(QString("<font color='cyan'>[RUN]</font> %1 using %2...").arg(selectedRole, algo));

    ui->progress_bar->setValue(0);

    // Fake animation
    for (int i = 0; i <= 100; i += 10) {
        QTimer::singleShot(i * 50, this, [this, i]() {
            ui->progress_bar->setValue(i);
        });
    }

    QTimer::singleShot(1000, this, [this, algo]() {
        manager->runRole(selectedRole, algo);
        ui->log_output->append("<font color='lime'>[DONE]</font> Task completed successfully!");
        QMessageBox::information(this, "Success", "✅ Task finished successfully!");
    });
}

PQC_GUI::~PQC_GUI()
{
    delete ui;
}
