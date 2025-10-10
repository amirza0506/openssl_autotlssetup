/********************************************************************************
** Form generated from reading UI file 'pqc_agent3.ui'
**
** Created by: Qt User Interface Compiler version 6.8.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_PQC_AGENT3_H
#define UI_PQC_AGENT3_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
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
    QProgressBar *progressBar;
    QPlainTextEdit *outputText;
    QPushButton *btnSelect;
    QPushButton *btnScan;

    void setupUi(QMainWindow *PQC_Agent)
    {
        if (PQC_Agent->objectName().isEmpty())
            PQC_Agent->setObjectName("PQC_Agent");
        PQC_Agent->resize(500, 400);
        centralwidget = new QWidget(PQC_Agent);
        centralwidget->setObjectName("centralwidget");
        verticalLayout = new QVBoxLayout(centralwidget);
        verticalLayout->setObjectName("verticalLayout");
        labelStatus = new QLabel(centralwidget);
        labelStatus->setObjectName("labelStatus");

        verticalLayout->addWidget(labelStatus);

        progressBar = new QProgressBar(centralwidget);
        progressBar->setObjectName("progressBar");
        progressBar->setValue(0);

        verticalLayout->addWidget(progressBar);

        outputText = new QPlainTextEdit(centralwidget);
        outputText->setObjectName("outputText");

        verticalLayout->addWidget(outputText);

        btnSelect = new QPushButton(centralwidget);
        btnSelect->setObjectName("btnSelect");

        verticalLayout->addWidget(btnSelect);

        btnScan = new QPushButton(centralwidget);
        btnScan->setObjectName("btnScan");

        verticalLayout->addWidget(btnScan);

        PQC_Agent->setCentralWidget(centralwidget);

        retranslateUi(PQC_Agent);

        QMetaObject::connectSlotsByName(PQC_Agent);
    } // setupUi

    void retranslateUi(QMainWindow *PQC_Agent)
    {
        PQC_Agent->setWindowTitle(QCoreApplication::translate("PQC_Agent", "PQC Agent", nullptr));
        labelStatus->setText(QCoreApplication::translate("PQC_Agent", "Ready.", nullptr));
        btnSelect->setText(QCoreApplication::translate("PQC_Agent", "Select Folder", nullptr));
        btnScan->setText(QCoreApplication::translate("PQC_Agent", "Scan", nullptr));
    } // retranslateUi

};

namespace Ui {
    class PQC_Agent: public Ui_PQC_Agent {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_PQC_AGENT3_H
