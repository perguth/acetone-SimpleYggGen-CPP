#include <QtCore>
#include "qtdownload.h"
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QtDownload dl;
    dl.setTarget("http://[324:9de3:fea4:f6ac::ace]/files/text/inception/readme.txt");

    dl.download();
    //quit when the download is done.
    QObject::connect(&dl, SIGNAL(done()), &app, SLOT(quit()));
    return app.exec();
}
