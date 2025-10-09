#include "pqc_gui.h"
#include <QApplication>

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    PQCGui w;
    w.show();
    return app.exec();
}
