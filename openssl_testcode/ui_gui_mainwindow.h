/********************************************************************************
** Form generated from reading UI file 'gui_mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 6.8.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_GUI_MAINWINDOW_H
#define UI_GUI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QWidget *centralwidget;
    QVBoxLayout *verticalLayout;
    QHBoxLayout *buttonLayout;
    QPushButton *btnClassical;
    QPushButton *btnPQC;
    QPushButton *btnKaz;
    QPushButton *btnHybrid;
    QTextEdit *outputText;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName("MainWindow");
        MainWindow->resize(600, 400);
        centralwidget = new QWidget(MainWindow);
        centralwidget->setObjectName("centralwidget");
        verticalLayout = new QVBoxLayout(centralwidget);
        verticalLayout->setObjectName("verticalLayout");
        buttonLayout = new QHBoxLayout();
        buttonLayout->setObjectName("buttonLayout");
        btnClassical = new QPushButton(centralwidget);
        btnClassical->setObjectName("btnClassical");

        buttonLayout->addWidget(btnClassical);

        btnPQC = new QPushButton(centralwidget);
        btnPQC->setObjectName("btnPQC");

        buttonLayout->addWidget(btnPQC);

        btnKaz = new QPushButton(centralwidget);
        btnKaz->setObjectName("btnKaz");

        buttonLayout->addWidget(btnKaz);

        btnHybrid = new QPushButton(centralwidget);
        btnHybrid->setObjectName("btnHybrid");

        buttonLayout->addWidget(btnHybrid);


        verticalLayout->addLayout(buttonLayout);

        outputText = new QTextEdit(centralwidget);
        outputText->setObjectName("outputText");
        outputText->setReadOnly(true);

        verticalLayout->addWidget(outputText);

        MainWindow->setCentralWidget(centralwidget);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QCoreApplication::translate("MainWindow", "Crypto API GUI", nullptr));
        btnClassical->setText(QCoreApplication::translate("MainWindow", "Classical (RSA)", nullptr));
        btnPQC->setText(QCoreApplication::translate("MainWindow", "PQC (Post-Quantum)", nullptr));
        btnKaz->setText(QCoreApplication::translate("MainWindow", "Kaz Algorithm", nullptr));
        btnHybrid->setText(QCoreApplication::translate("MainWindow", "Hybrid Mode", nullptr));
        outputText->setPlaceholderText(QCoreApplication::translate("MainWindow", "Output log will appear here...", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_GUI_MAINWINDOW_H
