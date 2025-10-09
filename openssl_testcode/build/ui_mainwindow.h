/********************************************************************************
** Form generated from reading UI file 'gui_mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 5.15.15
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPlainTextEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QWidget *centralwidget;
    QVBoxLayout *verticalLayout;
    QLabel *lblTitle;
    QHBoxLayout *buttonLayout;
    QPushButton *btnGenerate;
    QPushButton *btnSign;
    QPushButton *btnVerify;
    QPlainTextEdit *txtOutput;
    QMenuBar *menubar;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName(QString::fromUtf8("MainWindow"));
        MainWindow->resize(640, 480);
        centralwidget = new QWidget(MainWindow);
        centralwidget->setObjectName(QString::fromUtf8("centralwidget"));
        verticalLayout = new QVBoxLayout(centralwidget);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        lblTitle = new QLabel(centralwidget);
        lblTitle->setObjectName(QString::fromUtf8("lblTitle"));
        lblTitle->setAlignment(Qt::AlignCenter);
        lblTitle->setStyleSheet(QString::fromUtf8("font-weight: bold; font-size: 16pt;"));

        verticalLayout->addWidget(lblTitle);

        buttonLayout = new QHBoxLayout();
        buttonLayout->setObjectName(QString::fromUtf8("buttonLayout"));
        btnGenerate = new QPushButton(centralwidget);
        btnGenerate->setObjectName(QString::fromUtf8("btnGenerate"));

        buttonLayout->addWidget(btnGenerate);

        btnSign = new QPushButton(centralwidget);
        btnSign->setObjectName(QString::fromUtf8("btnSign"));

        buttonLayout->addWidget(btnSign);

        btnVerify = new QPushButton(centralwidget);
        btnVerify->setObjectName(QString::fromUtf8("btnVerify"));

        buttonLayout->addWidget(btnVerify);


        verticalLayout->addLayout(buttonLayout);

        txtOutput = new QPlainTextEdit(centralwidget);
        txtOutput->setObjectName(QString::fromUtf8("txtOutput"));
        txtOutput->setReadOnly(true);
        txtOutput->setStyleSheet(QString::fromUtf8("font-family: monospace; background-color: #f4f4f4;"));

        verticalLayout->addWidget(txtOutput);

        MainWindow->setCentralWidget(centralwidget);
        menubar = new QMenuBar(MainWindow);
        menubar->setObjectName(QString::fromUtf8("menubar"));
        MainWindow->setMenuBar(menubar);
        statusbar = new QStatusBar(MainWindow);
        statusbar->setObjectName(QString::fromUtf8("statusbar"));
        MainWindow->setStatusBar(statusbar);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QCoreApplication::translate("MainWindow", "OpenSSL GUI Crypto Platform", nullptr));
        lblTitle->setText(QCoreApplication::translate("MainWindow", "\360\237\247\251 OpenSSL Crypto API GUI", nullptr));
        btnGenerate->setText(QCoreApplication::translate("MainWindow", "\360\237\224\221 Generate", nullptr));
        btnSign->setText(QCoreApplication::translate("MainWindow", "\360\237\226\213 Sign", nullptr));
        btnVerify->setText(QCoreApplication::translate("MainWindow", "\360\237\224\215 Verify", nullptr));
        txtOutput->setPlaceholderText(QCoreApplication::translate("MainWindow", "Output and log messages will appear here...", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
