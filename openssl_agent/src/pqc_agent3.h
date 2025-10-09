#ifndef PQC_AGENT_H
#define PQC_AGENT_H

#include <QMainWindow>
#include <QTimer>

namespace Ui {
class PQC_Agent;
}

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
};

#endif // PQC_AGENT_H
