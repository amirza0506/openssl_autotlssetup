/********************************************************************************
** Form generated from reading UI file 'pqc_agent.ui'
**
** Created by: Qt User Interface Compiler version 6.8.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_PQC_AGENT_H
#define UI_PQC_AGENT_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QPlainTextEdit>
#include <QtWidgets/QProgressBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_PQC_Agent
{
public:
    QWidget *centralwidget;
    QVBoxLayout *verticalLayout;
    QLabel *labelStatus;
    QHBoxLayout *buttonLayout;
    QPushButton *btnSelect;
    QPushButton *btnScan;
    QPushButton *btnExport;
    QProgressBar *progressBar;
    QPlainTextEdit *outputText;

    void setupUi(QMainWindow *PQC_Agent)
    {
        if (PQC_Agent->objectName().isEmpty())
            PQC_Agent->setObjectName("PQC_Agent");
        PQC_Agent->resize(720, 480);
        centralwidget = new QWidget(PQC_Agent);
        centralwidget->setObjectName("centralwidget");
        verticalLayout = new QVBoxLayout(centralwidget);
        verticalLayout->setObjectName("verticalLayout");
        labelStatus = new QLabel(centralwidget);
        labelStatus->setObjectName("labelStatus");

        verticalLayout->addWidget(labelStatus);

        buttonLayout = new QHBoxLayout();
        buttonLayout->setObjectName("buttonLayout");
        btnSelect = new QPushButton(centralwidget);
        btnSelect->setObjectName("btnSelect");

        buttonLayout->addWidget(btnSelect);

        btnScan = new QPushButton(centralwidget);
        btnScan->setObjectName("btnScan");

        buttonLayout->addWidget(btnScan);

        btnExport = new QPushButton(centralwidget);
        btnExport->setObjectName("btnExport");

        buttonLayout->addWidget(btnExport);


        verticalLayout->addLayout(buttonLayout);

        progressBar = new QProgressBar(centralwidget);
        progressBar->setObjectName("progressBar");
        progressBar->setValue(0);

        verticalLayout->addWidget(progressBar);

        outputText = new QPlainTextEdit(centralwidget);
        outputText->setObjectName("outputText");
        outputText->setReadOnly(true);

        verticalLayout->addWidget(outputText);

        PQC_Agent->setCentralWidget(centralwidget);

        retranslateUi(PQC_Agent);

        QMetaObject::connectSlotsByName(PQC_Agent);
    } // setupUi

    void retranslateUi(QMainWindow *PQC_Agent)
    {
        PQC_Agent->setWindowTitle(QCoreApplication::translate("PQC_Agent", "PQC Agent", nullptr));
        labelStatus->setText(QCoreApplication::translate("PQC_Agent", "Select a folder to begin scanning.", nullptr));
        btnSelect->setText(QCoreApplication::translate("PQC_Agent", "Select Folder", nullptr));
        btnScan->setText(QCoreApplication::translate("PQC_Agent", "Start Scan", nullptr));
        btnExport->setText(QCoreApplication::translate("PQC_Agent", "Export Results", nullptr));
    } // retranslateUi

};

namespace Ui {
    class PQC_Agent: public Ui_PQC_Agent {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_PQC_AGENT_H
