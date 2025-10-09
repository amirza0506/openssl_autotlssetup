#ifndef PQC_GUI_H
#define PQC_GUI_H

#include <QWidget>
#include <QString>

QT_BEGIN_NAMESPACE
namespace Ui { class PQC_GUI; }
QT_END_NAMESPACE

class PQCManager;

class PQC_GUI : public QWidget
{
    Q_OBJECT

public:
    PQC_GUI(QWidget *parent = nullptr);
    ~PQC_GUI();

private slots:
    void refreshAlgorithms();
    void runTask();

private:
    Ui::PQC_GUI *ui;
    PQCManager *manager;
    QString selectedRole;
};

#endif // PQC_GUI_H
