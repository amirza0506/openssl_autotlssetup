#include "pqc_agent.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    PQC_Agent w;
    w.show();
    return a.exec();
}
