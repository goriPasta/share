#include "devlist.h"
#include "dev_choose.h"
#include "device.h"

int main(int argc, char* argv[]){
    pm::Machine m;
    pcap_if_t *ii;
    std::vector<std::string> devlist;
    char *err;
    int count=1;
    int devnum;

    if(pcap_findalldevs(&ii,err)!=0)printf("error\n");//get device

    for(pcap_if_t *de=ii;de;de=de->next){
        std::string device=std::string(de->name);
                std::cout<<count<<" "<< device<< std::endl;
                devlist.emplace_back(device);
                count++;
    }
    std::cout<<"デバイスを選んでください"<<std::endl;
    std::cin>>devnum;
    devnum--;//0スタートにする
    std::cout<<devlist[devnum]<<"でパケットキャプチャを実行します"<<std::endl;

}
DevListModel::DevListModel(QObject *parent):QAbstractListModel(parent){

}
DevListModel::~DevListModel(){
    while (!list.isEmpty()) {
        delete list.takeFirst();
    }
}
//return list data
QVariant DevListModel::data(const QModelIndex &index, int role)const{
    if(!index.isValid()||role!=Qt::DisplayRole){
        return QVariant();
        return list[index.row()]->getDevice();
    }
}

//add data
void DevListModel::add(Device *device){
    beginInsertRows(QModelIndex(),list.count(),list.count());
    list.append(device);
    endInsertRows();
}

Device::Device(QObject *parent):QObject(parent){

}
Device::Device(const QString &device,QObject *devdev):Device(devdev){
    this->device=device;
}
QString &Device::getDevice(){
    return this->device;
}
