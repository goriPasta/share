//パケットの中身を取得するクラスです。
#include "packet.h"

Packet::Packet(QObject *parent):QObject(parent)
{

}
Packet::Packet(const int number,
               //const double time,
               const QString &date,
               const QString &source,
               const QString &dest,
               const QString &protocol,
               const QString length,
               QObject *packet):Packet(packet)
{
    this->number=number;
    this->date=date;
    //this->time=time;
    this->source=source;
    this->dest=dest;
    this->protocol=protocol;
    this->length=length;
}
QString &Packet::getSource()
{
    return this->source;
}
QString &Packet::getDest()
{
    return this->dest;
}
QString &Packet::getProtocol()
{
    return this->protocol;
}
int Packet::getNumber()
{
    return this->number;
}
/*double Packet::getTime()
{
    return this->time;
}*/
QString &Packet::getDate()
{
    return this->date;
}
QString &Packet::getLength()
{
    return this->length;
}
std::vector<QString> Packet::getStatusVector(){
    std::vector<QString> statusvector;
    statusvector.emplace_back(date);
    statusvector.emplace_back(source);
    statusvector.emplace_back(dest);
    statusvector.emplace_back(length);
    statusvector.emplace_back(protocol);
    return statusvector;
}
