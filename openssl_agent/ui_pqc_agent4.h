/********************************************************************************
** Form generated from reading UI file 'pqc_agent4.ui'
**
** Created by: Qt User Interface Compiler version 6.8.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_PQC_AGENT4_H
#define UI_PQC_AGENT4_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QPlainTextEdit>
#include <QtWidgets/QProgressBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_PQC_Agent
{
public:
    QWidget *centralwidget;
    QVBoxLayout *verticalLayout;
    QHBoxLayout *buttonLayout;
    QPushButton *btnSelect;
    QPushButton *btnScan;
    QLabel *labelStatus;
    QProgressBar *progressBar;
    QPlainTextEdit *outputText;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *PQC_Agent)
    {
        if (PQC_Agent->objectName().isEmpty())
            PQC_Agent->setObjectName("PQC_Agent");
        PQC_Agent->resize(700, 500);
        centralwidget = new QWidget(PQC_Agent);
        centralwidget->setObjectName("centralwidget");
        verticalLayout = new QVBoxLayout(centralwidget);
        verticalLayout->setObjectName("verticalLayout");
        buttonLayout = new QHBoxLayout();
        buttonLayout->setObjectName("buttonLayout");
        btnSelect = new QPushButton(centralwidget);
        btnSelect->setObjectName("btnSelect");
        btnSelect->setMinimumWidth(120);
        btnSelect->setIconSize(QSize(24, 24));

        buttonLayout->addWidget(btnSelect);

        btnScan = new QPushButton(centralwidget);
        btnScan->setObjectName("btnScan");
        btnScan->setMinimumWidth(120);
        btnScan->setIconSize(QSize(24, 24));

        buttonLayout->addWidget(btnScan);


        verticalLayout->addLayout(buttonLayout);

        labelStatus = new QLabel(centralwidget);
        labelStatus->setObjectName("labelStatus");
        labelStatus->setAlignment(Qt::AlignCenter);
        labelStatus->setStyleSheet(QString::fromUtf8("font-weight: bold; color: #0055aa;"));

        verticalLayout->addWidget(labelStatus);

        progressBar = new QProgressBar(centralwidget);
        progressBar->setObjectName("progressBar");
        progressBar->setValue(0);
        progressBar->setTextVisible(true);
        progressBar->setMinimumHeight(20);

        verticalLayout->addWidget(progressBar);

        outputText = new QPlainTextEdit(centralwidget);
        outputText->setObjectName("outputText");
        outputText->setReadOnly(true);
        outputText->setStyleSheet(QString::fromUtf8("background-color: #f7f7f7; border: 1px solid #ccc; font-family: Consolas, monospace; font-size: 11pt;"));

        verticalLayout->addWidget(outputText);

        verticalLayout->setStretch(3, 1);
        PQC_Agent->setCentralWidget(centralwidget);
        statusbar = new QStatusBar(PQC_Agent);
        statusbar->setObjectName("statusbar");
        PQC_Agent->setStatusBar(statusbar);

        retranslateUi(PQC_Agent);

        QMetaObject::connectSlotsByName(PQC_Agent);
    } // setupUi

    void retranslateUi(QMainWindow *PQC_Agent)
    {
        PQC_Agent->setWindowTitle(QCoreApplication::translate("PQC_Agent", "PQC Agent - OpenSSL Scanner", nullptr));
        btnSelect->setText(QCoreApplication::translate("PQC_Agent", "\360\237\223\202 Select Folder", nullptr));
        btnScan->setText(QCoreApplication::translate("PQC_Agent", "\360\237\224\215 Start Scan", nullptr));
        labelStatus->setText(QCoreApplication::translate("PQC_Agent", "\360\237\222\244 Idle - No folder selected", nullptr));
        progressBar->setFormat(QCoreApplication::translate("PQC_Agent", "%p% Completed", nullptr));
        outputText->setPlaceholderText(QCoreApplication::translate("PQC_Agent", "Scan logs and OpenSSL algorithm listing will appear here...", nullptr));
    } // retranslateUi

};

namespace Ui {
    class PQC_Agent: public Ui_PQC_Agent {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_PQC_AGENT4_H
