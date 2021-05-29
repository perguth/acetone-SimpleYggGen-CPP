#include "widget.h"

#include <fstream>
#include <QApplication>
#include <QString>
#include <QIcon>

const QString PRODUCT_VERSION = "5.0-irontree";

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    Widget w;
    w.setFixedSize( QSize(510, 192));
    w.setWindowTitle("syg-cpp " + PRODUCT_VERSION + " (Qt)");
    QFont defaultFont("PT Mono");
    defaultFont.setStyleHint(QFont::Monospace);
    a.setFont(defaultFont);

    w.setWindowIcon(QIcon(":/icon.png"));
    w.show();
    return a.exec();
}
