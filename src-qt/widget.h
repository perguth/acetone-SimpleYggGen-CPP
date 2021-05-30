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
    void setLog(std::string tm, uint64_t tt, uint64_t f, uint64_t k);
    void setAddr(std::string address);
    option conf;
    ~Widget();

private:
    Ui::Widget *ui;
    unsigned int m_mode = 1;
    uint64_t speedRecord = 0;
    void restoreNotABugLinkButton();

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

    void start();
    void stop();
    void changeBanner();
};
#endif // WIDGET_H
