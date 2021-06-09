#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include "configure.h"

QT_BEGIN_NAMESPACE
namespace Ui { class Widget; }
QT_END_NAMESPACE

class Widget : public QWidget
{
    Q_OBJECT

public:
    Widget(QWidget *parent = nullptr);
    option conf;
    ~Widget();

private:
    Ui::Widget *ui;
    unsigned int m_mode = 1;
    uint64_t speedRecord = 0;
    bool isStarted = false;
    QString numToReadableString(const quint64);

public slots:
    void secondByteEdit(int);
    void ipv6_pat_mode();
    void high_mode();
    void ipv6_pat_high_mode();
    void ipv6_reg_mode();
    void ipv6_reg_high_mode();
    void mesh_pat_mode();
    void mesh_reg_mode();

    void altitude_status(bool);
    void string_status(bool);

    void action();
    void changeBanner();

    void setAddr(const QString address);
    void setLog(const QString, const quint64, const quint64, const quint64);
};
#endif // WIDGET_H
