/********************************************************************************
** Form generated from reading UI file 'pqc_gui.ui'
**
** Created by: Qt User Interface Compiler version 6.8.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_PQC_GUI_H
#define UI_PQC_GUI_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QProgressBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_PQC_GUI
{
public:
    QVBoxLayout *verticalLayout;
    QLabel *label_title;
    QGroupBox *group_role;
    QHBoxLayout *horizontalLayout_role;
    QPushButton *btn_ca;
    QPushButton *btn_server;
    QPushButton *btn_client;
    QGroupBox *group_algo;
    QHBoxLayout *horizontalLayout_algo;
    QComboBox *combo_algo;
    QPushButton *btn_refresh;
    QPushButton *btn_run;
    QProgressBar *progress_bar;
    QTextEdit *log_output;

    void setupUi(QWidget *PQC_GUI)
    {
        if (PQC_GUI->objectName().isEmpty())
            PQC_GUI->setObjectName("PQC_GUI");
        PQC_GUI->resize(600, 400);
        verticalLayout = new QVBoxLayout(PQC_GUI);
        verticalLayout->setObjectName("verticalLayout");
        label_title = new QLabel(PQC_GUI);
        label_title->setObjectName("label_title");
        label_title->setAlignment(Qt::AlignCenter);
        label_title->setStyleSheet(QString::fromUtf8("font-size: 18px; font-weight: bold; color: #00bfa5;"));

        verticalLayout->addWidget(label_title);

        group_role = new QGroupBox(PQC_GUI);
        group_role->setObjectName("group_role");
        horizontalLayout_role = new QHBoxLayout(group_role);
        horizontalLayout_role->setObjectName("horizontalLayout_role");
        btn_ca = new QPushButton(group_role);
        btn_ca->setObjectName("btn_ca");

        horizontalLayout_role->addWidget(btn_ca);

        btn_server = new QPushButton(group_role);
        btn_server->setObjectName("btn_server");

        horizontalLayout_role->addWidget(btn_server);

        btn_client = new QPushButton(group_role);
        btn_client->setObjectName("btn_client");

        horizontalLayout_role->addWidget(btn_client);


        verticalLayout->addWidget(group_role);

        group_algo = new QGroupBox(PQC_GUI);
        group_algo->setObjectName("group_algo");
        horizontalLayout_algo = new QHBoxLayout(group_algo);
        horizontalLayout_algo->setObjectName("horizontalLayout_algo");
        combo_algo = new QComboBox(group_algo);
        combo_algo->setObjectName("combo_algo");

        horizontalLayout_algo->addWidget(combo_algo);

        btn_refresh = new QPushButton(group_algo);
        btn_refresh->setObjectName("btn_refresh");

        horizontalLayout_algo->addWidget(btn_refresh);


        verticalLayout->addWidget(group_algo);

        btn_run = new QPushButton(PQC_GUI);
        btn_run->setObjectName("btn_run");
        btn_run->setStyleSheet(QString::fromUtf8("font-size: 16px; background-color: #0078d7; color: white; border-radius: 8px; padding: 8px;"));

        verticalLayout->addWidget(btn_run);

        progress_bar = new QProgressBar(PQC_GUI);
        progress_bar->setObjectName("progress_bar");
        progress_bar->setMinimum(0);
        progress_bar->setMaximum(100);
        progress_bar->setValue(0);

        verticalLayout->addWidget(progress_bar);

        log_output = new QTextEdit(PQC_GUI);
        log_output->setObjectName("log_output");
        log_output->setReadOnly(true);
        log_output->setStyleSheet(QString::fromUtf8("background-color: #111; color: #00ffcc; font-family: monospace;"));

        verticalLayout->addWidget(log_output);


        retranslateUi(PQC_GUI);

        QMetaObject::connectSlotsByName(PQC_GUI);
    } // setupUi

    void retranslateUi(QWidget *PQC_GUI)
    {
        PQC_GUI->setWindowTitle(QCoreApplication::translate("PQC_GUI", "PQC Certificate Automation", nullptr));
        label_title->setText(QCoreApplication::translate("PQC_GUI", "\360\237\247\240 Post-Quantum Cryptography Toolkit", nullptr));
        group_role->setTitle(QCoreApplication::translate("PQC_GUI", "Step 1: Select Role", nullptr));
        btn_ca->setText(QCoreApplication::translate("PQC_GUI", "CA", nullptr));
        btn_server->setText(QCoreApplication::translate("PQC_GUI", "Server", nullptr));
        btn_client->setText(QCoreApplication::translate("PQC_GUI", "Client", nullptr));
        group_algo->setTitle(QCoreApplication::translate("PQC_GUI", "Step 2: Select Algorithm", nullptr));
        btn_refresh->setText(QCoreApplication::translate("PQC_GUI", "\360\237\224\204 Refresh", nullptr));
        btn_run->setText(QCoreApplication::translate("PQC_GUI", "\360\237\232\200 Run Task", nullptr));
    } // retranslateUi

};

namespace Ui {
    class PQC_GUI: public Ui_PQC_GUI {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_PQC_GUI_H
