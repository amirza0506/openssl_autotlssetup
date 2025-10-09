#pragma once
#include <QMainWindow>
#include <QTimer>

QT_BEGIN_NAMESPACE
namespace Ui { class PQC_Agent; }
QT_END_NAMESPACE

class PQC_Agent : public QMainWindow
{
    Q_OBJECT

public:
    explicit PQC_Agent(QWidget *parent = nullptr);
    ~PQC_Agent();

private slots:
    void selectFolder();
    void startScan();
    void updateProgress();

private:
    Ui::PQC_Agent *ui;
    QString selectedFolder;
    QTimer *progressTimer;
    int progressValue;

    void saveResultsToFiles(const QStringList &results);
};
