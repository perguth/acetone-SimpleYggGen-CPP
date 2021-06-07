#include "widget.h"
#include "qtdownload.h"

#include <fstream>
#include <QApplication>
#include <QString>
#include <QIcon>

const QString PRODUCT_VERSION = "5.1 flow";

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    Widget w;
    w.setWindowTitle("syg-cpp " + PRODUCT_VERSION + " (Qt)");
    QFont defaultFont("PT Mono");
    defaultFont.setStyleHint(QFont::Monospace);
    a.setFont(defaultFont);

    QtDownload dl;
    dl.setTarget("https://raw.githubusercontent.com/acetoneRu/files/main/syg-cpp-banner.png");
    dl.download();
    QObject::connect(&dl, SIGNAL(done()), &w, SLOT(changeBanner()));

    w.setWindowIcon(QIcon(":/icon.png"));
    w.show();
    return a.exec();
}
