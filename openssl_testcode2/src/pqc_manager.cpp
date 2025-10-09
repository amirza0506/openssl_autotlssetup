#include "pqc_manager.h"
#include <QProcess>
#include <QDebug>

PQCManager::PQCManager(QObject *parent)
    : QObject(parent)
{
}

void PQCManager::runRole(const QString &role, const QString &algo)
{
    qDebug() << "Running role:" << role << "with algorithm:" << algo;

    // You can later replace this with actual OpenSSL commands
    QString command;

    if (role == "CA") {
        command = QString("echo 'Running CA setup with %1'").arg(algo);
    } else if (role == "Server") {
        command = QString("echo 'Starting Server with %1'").arg(algo);
    } else if (role == "Client") {
        command = QString("echo 'Starting Client with %1'").arg(algo);
    } else {
        command = "echo 'Unknown role'";
    }

    QProcess process;
    process.start("bash", QStringList() << "-c" << command);
    process.waitForFinished();

    QString output = process.readAllStandardOutput();
    qDebug() << output;
}

