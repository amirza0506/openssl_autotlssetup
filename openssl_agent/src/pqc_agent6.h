#ifndef PQC_AGENT_H
#define PQC_AGENT_H

#include <QMainWindow>
#include <QTimer>
#include <QStringList>

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
    void scanNextFile();
    void updateProgress();

private:
    Ui::PQC_Agent *ui;
    QTimer *progressTimer;
    QString selectedFolder;
    QStringList scannedFiles;
    int currentFileIndex;
    int progressValue;
};

#endif // PQC_AGENT_H
