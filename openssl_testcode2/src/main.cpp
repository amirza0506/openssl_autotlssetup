#include <QApplication>
#include "pqc_gui.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    PQC_GUI window;
    window.show();

    return app.exec();
}
