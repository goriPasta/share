#ifndef DEVLIST_H
#define DEVLIST_H
#include <QAbstractTableModel>
#include <QVector>
#include "device.h"

class DevListModel: public QAbstractListModel{
    Q_OBJECT
public:
    explicit DevListModel(QObject *parent = nullptr);
    virtual ~DevListModel()override;
    //データを返す
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole)const override;
    //ヘッダを返す
    QVariant headerData(int section, Qt::Orientation orientation, int role=Qt::DisplayRole)const override;
    //add data
    void add(Device *device);
private:
    QVector<Device*>list;
};
#endif // DEVLIST_H
