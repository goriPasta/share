#ifndef WIDGET_H
#define WIDGET_H
#include <QWidget>
#include <packetmachine.hpp>
#include <string>
//#include "listmodel.h"
#include "packetlistmodel.h"
#include "deviceselect.h"
#include<pcap.h>
namespace Ui {
class Widget;
}
class Widget : public QWidget
{
  Q_OBJECT
public:
  explicit Widget(QWidget *parent = nullptr);
  ~Widget();
  //void capture(std::string);
  pm::Machine m;
private:
  Ui::Widget *ui;
  DeviceSelect *ds;
  ListModel *model;
public slots:
private slots:
  void on_pushButton_clicked(bool checked);
  void on_pushButton_clicked();
  void capture(QString);
};
#endif // WIDGET_H
