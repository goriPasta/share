#ifndef PACKETLISTMODEL_H
#define PACKETLISTMODEL_H

#include <QAbstractTableModel>
#include <QVector>
#include "packet.h"

class ListModel:public QAbstractTableModel
{
    Q_OBJECT
public:
    explicit ListModel(QObject *parent = nullptr);

    virtual ~ListModel() override;
    //列を返す
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    //行を返す
    int rowCount(const QModelIndex &parent = QModelIndex())const override;
    //データを返す
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole)const override;
    //ヘッダを返す
    QVariant headerData(int section, Qt::Orientation orientation, int role=Qt::DisplayRole)const override;
    //データの追加
    void add(Packet *packet);
    Packet* getPacket(double);
    int getSizeofList();
    void clearList();
private:
    //実際のデータ配列
    QVector<Packet*>list;
};

#endif // PACKETLISTMODEL_H
