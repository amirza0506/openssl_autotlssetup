#include "pqc_agent.h"
#include <QApplication>
#include <QCommandLineParser>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    QCommandLineParser parser;
    parser.addOption({{"n", "nogui"}, "Run without GUI"});
    parser.addPositionalArgument("folder", "Folder to scan");
    parser.process(a);

    bool noGui = parser.isSet("nogui");
    QStringList args = parser.positionalArguments();

    if (noGui && !args.isEmpty()) {
        PQC_Agent agent;
        agent.runHeadlessScan(args.first());
        return 0;
    }

    PQC_Agent w;
    w.show();
    return a.exec();
}
