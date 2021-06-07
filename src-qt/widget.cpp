#include "widget.h"
#include "ui_widget.h"
#include "configure.h"
#include "miner.h"
#include "qtdownload.h"

#include <QDir>
#include <iomanip>
#include <thread>
#include <sstream>
#include <future>
#include <iostream>
#include <QString>

Widget * widgetForMiner = nullptr;
miner * worker = nullptr;

void make_miner()
{
    worker = new miner(widgetForMiner);
    while (worker == nullptr) std::this_thread::sleep_for(std::chrono::milliseconds(50));
    worker->startThreads();
}

Widget::Widget(QWidget *parent): QWidget(parent), ui(new Ui::Widget)
{
    ui->setupUi(this);

    unsigned int processor_count = std::thread::hardware_concurrency();
    ui->threads->setMaximum(processor_count);
    ui->threads->setValue(processor_count);

    ui->action->setShortcut(Qt::Key_Return | Qt::Key_Enter);

    QObject::connect(ui->height, SIGNAL(valueChanged(int)), this, SLOT(secondByteEdit(int)));
    QObject::connect(ui->action, SIGNAL(clicked()), this, SLOT(action()));

    QObject::connect(ui->ipv6_pat_mode,      SIGNAL(clicked()), this, SLOT(ipv6_pat_mode()));
    QObject::connect(ui->high_mode,          SIGNAL(clicked()), this, SLOT(high_mode()));
    QObject::connect(ui->ipv6_pat_high_mode, SIGNAL(clicked()), this, SLOT(ipv6_pat_high_mode()));
    QObject::connect(ui->ipv6_reg_mode,      SIGNAL(clicked()), this, SLOT(ipv6_reg_mode()));
    QObject::connect(ui->ipv6_reg_high_mode, SIGNAL(clicked()), this, SLOT(ipv6_reg_high_mode()));
    QObject::connect(ui->mesh_pat_mode,      SIGNAL(clicked()), this, SLOT(mesh_pat_mode()));
    QObject::connect(ui->mesh_reg_mode,      SIGNAL(clicked()), this, SLOT(mesh_reg_mode()));

    ui->label->setToolTip("acetone@i2pmail.org");
    ui->path->setText(QDir::currentPath());
    this->setFixedSize(this->size());
}

void Widget::setLog(QString tm, quint64 tt, quint64 f, quint64 k)
{
    if (k > speedRecord) { // максимальная скорость
        speedRecord = k;
        std::string hs = "Maximum speed: " + std::to_string(speedRecord) + " kH/s";
        ui->hs->setText(hs.c_str());
    }
    ui->time->setText(tm);                          // время
    ui->total->setText(std::to_string(tt).c_str()); // общий счетчик
    ui->found->setText(std::to_string(f).c_str());  // колесо фартуны
    ui->khs->setText(std::to_string(k).c_str());    // скорость
}

void Widget::setAddr(QString address)
{
    ui->last->setText(address);
}

Widget::~Widget()
{
    delete ui;
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
}

void Widget::action()
{
    if (isStarted) {
        worker->conf.stop = true;
        isStarted = false;
        ui->khs->setNum(0);
        ui->stackedWidget->setCurrentIndex(0);
        ui->action->setText("START");
        ui->action->setShortcut(Qt::Key_Return | Qt::Key_Enter);
        return;
    }

    if (ui->stringSet->text() == "" && m_mode != 1) {
        ui->stringSet->setPlaceholderText("PATTERN/REGEXP");
        return;
    }

    ui->stackedWidget->setCurrentIndex(1);
    ui->last->setText("<last address will be here>");
    ui->hs->setText("Maximum speed: 0 kH/s");
    setLog("00:00:00:00", 0, 0, 0);
    speedRecord = 0;

    conf.mode   = m_mode;
    conf.proc   = ui->threads->value();
    conf.high   = ui->height->value();
    conf.str    = ui->stringSet->text().toStdString();
    conf.letsup = !ui->disableIncrease->isChecked();
    conf.stop   = false;

    widgetForMiner = this;
    isStarted = true;
    ui->action->setText("STOP");
    ui->action->setShortcut(Qt::Key_Return | Qt::Key_Enter);
    std::thread(make_miner).detach();
}

void Widget::changeBanner()
{
    QFile banner("ad.png");
    if (banner.size() > 5)
    {
        QPixmap adBanner;
        adBanner.load("ad.png");
        ui->label->setPixmap(adBanner);
    }
    banner.remove();
}
