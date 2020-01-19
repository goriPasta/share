#ifndef PACKET_H
#define PACKET_H

#include <QObject>
#include <QString>

class Packet : public QObject
{
    Q_OBJECT
public:
    explicit Packet(QObject *parent = nullptr);//ヌルポインタを設定
    Packet(const int number,
           //const double time,
           const QString &date,
           const QString &source,
           const QString &dest,
           const QString &protocol,
           const QString length,
           QObject *parent = nullptr);

signals:

public slots:

private:
    int number;
    //double time;
    QString date,source,dest,protocol,length;
public:
    QString &getDate(),&getSource(),&getDest(),&getProtocol(),&getLength();
    int getNumber();
    //double getTime();
    std::vector<QString> getStatusVector();
};

#endif // PACKET_H
