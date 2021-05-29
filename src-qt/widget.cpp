#include "widget.h"
#include "ui_widget.h"
#include "configure.h"
#include "miner.h"

#include <QDir>
#include <iomanip>
#include <thread>
#include <sstream>
#include <future>
#include <iostream>
#include <QString>
#include <QClipboard>

Widget* widgetForMiner;
miner * worker = nullptr;

void make_miner()
{
    worker = new miner(widgetForMiner);
    while (worker == nullptr) std::this_thread::sleep_for(std::chrono::milliseconds(500));
    worker->startThreads();
}

Widget::Widget(QWidget *parent): QWidget(parent), ui(new Ui::Widget)
{
    ui->setupUi(this);
    ui->frame_2->hide();

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
    QObject::connect(ui->mesh_reg_mode, SIGNAL(clicked()), this, SLOT(mesh_reg_mode()));

    QObject::connect(ui->stop, SIGNAL(clicked()), this, SLOT(stop()));

    QClipboard* c = QApplication::clipboard();
    QObject::connect(ui->notabugLink, &QPushButton::clicked, c, [&]()
    {
        c->setText("https://notabug.org/acetone/SimpleYggGen-CPP");
        ui->notabugLink->setText("Сopied to clipboard");
        QFont font;
        font.setItalic(true);
        font.setPointSize(8);
        ui->notabugLink->setFont(font);
        std::thread (&Widget::restoreNotABugLinkButton, this).detach(); // TODO async
    });
}

void Widget::setLog(std::string tm, uint64_t tt, uint64_t f, uint64_t k)
{
    ui->time->setText(tm.c_str());                  // время
    ui->total->setText(std::to_string(tt).c_str()); // общий счетчик
    ui->found->setText(std::to_string(f).c_str());  // общий счетчик
    ui->khs->setText(std::to_string(k).c_str());    // скорость

    std::string hs = std::to_string(k*1000) + " per second";
    ui->hs->setText(hs.c_str());
}

void Widget::setAddr(std::string address)
{
    ui->last->setText(address.c_str());
}

Widget::~Widget()
{
    delete ui;
}

void Widget::restoreNotABugLinkButton()
{
    std::this_thread::sleep_for(std::chrono::seconds(3));
    QFont font;
    font.setItalic(false);
    font.setPointSize(8);
    ui->notabugLink->setFont(font);
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
    m_mode = 0;
    string_status(true);
    altitude_status(false);
}

void Widget::high_mode()
{
    m_mode = 1;
    altitude_status(true);
    string_status(false);
}

void Widget::ipv6_pat_high_mode()
{
    m_mode = 2;
    altitude_status(true);
    string_status(true);
}

void Widget::ipv6_reg_mode()
{
    m_mode = 3;
    string_status(true);
    altitude_status(false);
}

void Widget::ipv6_reg_high_mode()
{
    m_mode = 4;
    altitude_status(true);
    string_status(true);
}

void Widget::mesh_pat_mode()
{
    m_mode = 5;
    string_status(true);
    altitude_status(false);
}

void Widget::mesh_reg_mode()
{
    m_mode = 6;
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
    if (ui->stringSet->text() == "" && m_mode != 1) {
        ui->stringSet->setPlaceholderText("???");
        return;
    }

    ui->frame->hide();
    ui->frame_2->show();
    ui->frame_2->setGeometry(10, 10, 491, 161);

    conf.mode   = m_mode;
    conf.proc   = ui->threads->value();
    conf.high   = ui->height->value();
    conf.str    = ui->stringSet->text().toStdString();
    conf.letsup = !ui->disableIncrease->isChecked();

    ui->path->setText(QDir::currentPath());

    widgetForMiner = this;
    std::thread(make_miner).detach();
}

void Widget::stop()
{
    worker->conf.stop = true;
    ui->frame->show();
    ui->frame_2->hide();
}
