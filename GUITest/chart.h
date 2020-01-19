
#ifndef CHART_H
#define CHART_H

#include <QtCharts/QChart>
#include <QtCore/QTimer>
#include "mainwindow.h"

QT_CHARTS_BEGIN_NAMESPACE
class QLineSeries;
class QValueAxis;
QT_CHARTS_END_NAMESPACE

QT_CHARTS_USE_NAMESPACE

//![1]
class Chart: public QChart
{
    Q_OBJECT
public:
    Chart(QGraphicsItem *parent = 0, Qt::WindowFlags wFlags = 0);
    virtual ~Chart();
    MainWindow *mw;
    int nowy;

public slots:
    void handleTimeout();

private:
    QTimer m_timer;
    QLineSeries *m_series;
    QStringList m_titles;
    QValueAxis *m_axisX;
    QValueAxis *m_axisY;
    qreal m_step;
    qreal m_x;
    qreal m_y;
};
//![1]

#endif /* CHART_H */
