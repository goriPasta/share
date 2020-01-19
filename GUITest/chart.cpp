

#include "chart.h"
#include <QtCharts/QAbstractAxis>
#include <QtCharts/QSplineSeries>
#include <QtCharts/QLineSeries>
#include <QtCharts/QValueAxis>
#include <QtCore/QRandomGenerator>
#include <QtCore/QDebug>
#include <time.h>

Chart::Chart(QGraphicsItem *parent, Qt::WindowFlags wFlags):
    QChart(QChart::ChartTypeCartesian, parent, wFlags),
    m_series(0),
    m_axisX(new QValueAxis()),
    m_axisY(new QValueAxis()),
    m_step(0),
    m_x(0),
    m_y(0)
{
    time_t time(time_t *t);
    QObject::connect(&m_timer, &QTimer::timeout, this, &Chart::handleTimeout);
    m_timer.setInterval(1000);

    m_series = new QLineSeries(this);
    QPen green(Qt::red);
    green.setWidth(3);
    m_series->setPen(green);
    m_series->append(m_x, m_y);

    addSeries(m_series);
    m_axisX->setGridLineVisible(false);
    addAxis(m_axisX,Qt::AlignBottom);
    addAxis(m_axisY,Qt::AlignLeft);
    m_series->attachAxis(m_axisX);
    m_series->attachAxis(m_axisY);
    m_axisX->setTickCount(1);
    m_axisX->setRange(0, 1);
    m_axisY->setRange(0,20);
    m_axisX->setTitleText("time [s]");
    m_axisY->setTitleText("traffic [Packet/s]");
    nowy=20;

    m_timer.start();
}

Chart::~Chart()
{

}

void Chart::handleTimeout()
{
    time_t t;
    int totalsize=0;
    int nowbottom=0;
    bool ok;
    static int i=0;
    //if(nowbottom==mw->getModel()->getSizeofList());
    //else{
        for(i;i<mw->getModel()->getSizeofList();i++){

            totalsize+=1;
            //QString::to
        }
    //}

    //nowbottom=i;

    qreal x = plotArea().width() / m_axisX->tickCount();
    qreal y = (m_axisX->max() - m_axisX->min()) / m_axisX->tickCount();
    m_x =(mw->et2.elapsed())/1000;
    m_y = totalsize;
    m_series->append(m_x, m_y);
    int tk=m_x+2;
    while(tk>7){
        tk=tk/2;
    }
    m_axisX->setTickCount(tk);

    if(m_x>1){
        m_axisX->setRange(0, m_x);
    }
    if(m_y>nowy){
        m_axisY->setRange(0,m_y+10);
        nowy=m_y;
    }
    //scroll(x, y);

    totalsize=0;

}
