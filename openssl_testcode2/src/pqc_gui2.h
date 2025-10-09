#pragma once
#include <QMainWindow>
#include "pqc_manager.h"

QT_BEGIN_NAMESPACE
namespace Ui { class PQCGui; }
QT_END_NAMESPACE

class PQCGui : public QMainWindow {
    Q_OBJECT
public:
    explicit PQCGui(QWidget *parent = nullptr);
    ~PQCGui();

private slots:
    void onRunClicked();

private:
    Ui::PQCGui *ui;
    PQCManager *manager;
};
