#ifndef PQC_AGENT_H
#define PQC_AGENT_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class PQC_Agent; }
QT_END_NAMESPACE

class PQC_Agent : public QMainWindow {
    Q_OBJECT

public:
    explicit PQC_Agent(QWidget *parent = nullptr);
    ~PQC_Agent();

private slots:
    void on_scanButton_clicked();
    void on_exportButton_clicked();

private:
    Ui::PQC_Agent *ui;
    void scanFile(const QString &filePath);
};

#endif // PQC_AGENT_H
