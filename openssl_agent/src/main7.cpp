#include "pqc_agent.h"
#include <QApplication>

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    PQC_Agent window;
    window.show();
    return app.exec();
}
