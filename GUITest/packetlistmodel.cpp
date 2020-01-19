//取得したデータからテーブルを生成するための処理を行うクラスです。モデル生成をする。
#include "packetlistmodel.h"

ListModel::ListModel(QObject *parent):QAbstractTableModel(parent)
{

}
ListModel::~ListModel()
{
    while(!list.isEmpty()){
        delete list.takeFirst();
    }
}

//列数を返す
int ListModel::columnCount(const QModelIndex &parent) const{
    return 6;
}
//行数を返す
int ListModel::rowCount(const QModelIndex &parent) const{
    return list.count();
}
//データを返す
QVariant ListModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid()||role != Qt::DisplayRole){
        return QVariant();
    }
    switch (index.column()) {
    case 0:
        return list[index.row()]->getNumber();
    case 1:
        return list[index.row()]->getDate();
    case 2:
        return list[index.row()]->getSource();
    case 3:
        return list[index.row()]->getDest();
    case 4:
        return list[index.row()]->getLength();
    case 5:
        return list[index.row()]->getProtocol();
    default:
        return QVariant();
    }
}
//ヘッダを返す
QVariant ListModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(role != Qt::DisplayRole){
        return QVariant();
    }
    if(orientation == Qt::Horizontal){
        switch (section) {
        case 0:
            return tr("No.");
        case 1:
            return tr("Date");
        case 2:
            return tr("Source");
        case 3:
            return tr("Destination");
        case 4:
            return tr("Length");
        case 5:
            return tr("Protocol");
        default:
            return QVariant();
        }
    }else{
        return QVariant(section+1);
    }
}
//データの追加
void ListModel::add(Packet *packet)
{
    beginInsertRows(QModelIndex(),list.count(),list.count());
    list.append(packet);
    endInsertRows();
}
int ListModel::getSizeofList(){
    return list.size();
}
void ListModel::clearList(){
    list.clear();
    this->resetInternalData();
}
Packet* ListModel::getPacket(double index){
    return list[index];
}
