#ifndef DEVICE_H
#define DEVICE_H
#include <QObject>
#include <QString>

class Device:public QObject{
    Q_OBJECT
public:
    explicit Device(QObject *parent = nullptr);
    Device(const QString &device,
           QObject *patrent=nullptr);
signals:
public slots:
private:
    QString device;
public:
    QString &getDevice();
};
#endif // DEVICE_H
