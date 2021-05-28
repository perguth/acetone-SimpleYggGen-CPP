#include "widget.h"

#include <QApplication>
#include <QString>

const QString PRODUCT_VERSION = "5.0-irontree";

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    Widget w;
    w.setFixedSize( QSize(510, 293));
    w.setWindowTitle("SYG-CPP " + PRODUCT_VERSION + " (Qt)");
    QFont defaultFont("PT Mono");
    defaultFont.setStyleHint(QFont::Monospace);
    a.setFont(defaultFont);

    w.show();
    return a.exec();
}
