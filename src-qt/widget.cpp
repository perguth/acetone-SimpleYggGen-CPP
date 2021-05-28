#include "widget.h"
#include "ui_widget.h"

#include <iomanip>
#include <thread>
#include <sstream>
#include <future>
#include <QString>
#include <QClipboard>

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
    ui->frame_2->setDisabled(true);

    unsigned int processor_count = std::thread::hardware_concurrency();
    ui->threads->setMaximum(processor_count);
    ui->threads->setValue(processor_count);

    QObject::connect(ui->height, SIGNAL(valueChanged(int)), this, SLOT(secondByteEdit(int)));
    QObject::connect(ui->startMining, SIGNAL(clicked()), this, SLOT(start()));

    QObject::connect(ui->ipv6_pat_mode, SIGNAL(clicked()), this, SLOT(ipv6_pat_mode()));
    QObject::connect(ui->high_mode, SIGNAL(clicked()), this, SLOT(high_mode()));
    QObject::connect(ui->ipv6_pat_high_mode, SIGNAL(clicked()), this, SLOT(ipv6_pat_high_mode()));
    QObject::connect(ui->ipv6_reg_mode, SIGNAL(clicked()), this, SLOT(ipv6_reg_mode()));
    QObject::connect(ui->ipv6_reg_high_mode, SIGNAL(clicked()), this, SLOT(ipv6_reg_high_mode()));
    QObject::connect(ui->mesh_pat_mode, SIGNAL(clicked()), this, SLOT(mesh_pat_mode()));

    QObject::connect(ui->stop, SIGNAL(clicked()), this, SLOT(stop()));

    QClipboard* c = QApplication::clipboard();
    QObject::connect(ui->notabugLink, &QPushButton::clicked, c, [&]()
    {
        c->setText("https://notabug.org/acetone/SimpleYggGen-CPP");
        ui->notabugLink->setText("Сopied to clipboard");
        std::thread (&Widget::restoreNotABugLinkButton, this); // TODO async
    });
}

Widget::~Widget()
{
    delete ui;
}

void Widget::restoreNotABugLinkButton()
{
    std::this_thread::sleep_for(std::chrono::seconds(3));
    ui->notabugLink->setText("NotABug.org/acetone/SimpleYggGen-CPP");
}

void Widget::secondByteEdit(int i)
{
    std::stringstream ss;
    ss << std::setw(2) << std::setfill('0') << std::hex << i ;
    ui->secondByte->setText(ss.str().c_str());
}

void Widget::ipv6_pat_mode()
{
    mode = 0;
    string_status(true);
    altitude_status(false);
}

void Widget::high_mode()
{
    mode = 1;
    altitude_status(true);
    string_status(false);
}

void Widget::ipv6_pat_high_mode()
{
    mode = 2;
    altitude_status(true);
    string_status(true);
}

void Widget::ipv6_reg_mode()
{
    mode = 3;
    string_status(true);
    altitude_status(false);
}

void Widget::ipv6_reg_high_mode()
{
    mode = 4;
    altitude_status(true);
    string_status(true);
}

void Widget::mesh_pat_mode()
{
    mode = 5;
    string_status(true);
    altitude_status(false);
}

void Widget::mesh_reg_mode()
{
    mode = 6;
    string_status(true);
    altitude_status(false);
}

void Widget::altitude_status(bool b)
{
    ui->x_startaltitude->setEnabled(b);
    ui->x_firstByte->setEnabled(b);
    ui->secondByte->setEnabled(b);
    ui->x_doubledot->setEnabled(b);
    ui->height->setEnabled(b);
    ui->disableIncrease->setEnabled(b);
}

void Widget::string_status(bool b)
{
    ui->stringSet->setEnabled(b);
    ui->x_string->setEnabled(b);
}

void Widget::start()
{
    ui->frame->setDisabled(true);
    ui->frame_2->setDisabled(false);
}

void Widget::stop()
{
    ui->frame->setDisabled(false);
    ui->frame_2->setDisabled(true);
}
