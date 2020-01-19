#include "deviceselect.h"
#include "ui_deviceselect.h"
#include<pcap.h>

DeviceSelect::DeviceSelect(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DeviceSelect)
{
    ui->setupUi(this);

    comb = new QComboBox(this);
    BL=new QFormLayout(this);
    chek[0] = new QCheckBox("TCP",this);
    chek[1] = new QCheckBox("UDP",this);
    chek[2] = new QCheckBox("DNS",this);
    chek[3] = new QCheckBox("ARP",this);
    chek[4] = new QCheckBox("ICMP",this);
    chek[5] = new QCheckBox("DHCP",this);

    BL->addWidget(chek[0]);
    BL->addWidget(chek[1]);
    BL->addWidget(chek[2]);
    BL->addWidget(chek[3]);
    BL->addWidget(chek[4]);
    BL->addWidget(chek[5]);

    //QVBoxLayout *lo= new QVBoxLayout();

    pcap_if_t *ii;
        std::string dev;
        std::vector<std::string> devlist;
        int count=1;
        int devnum;
        char *err;
    if(pcap_findalldevs(&ii,err)!=0) printf("error\n");//デバイス名の取得


        for(pcap_if_t *de=ii;de;de=de->next){//デバイス名の一覧表示とvectorへの格納

            std::string device=std::string(de->name);
            comb->addItem(device.c_str());
            //devlist.emplace_back(device);
            count++;
        }
    comb->setGeometry(30,230,180,30);
    setLayout(BL);
    //wi=dynamic_cast<Widget*>(parent);
        connect(ui->buttonBox,SIGNAL(accepted()),parent,SLOT(capture(QString)));

}
DeviceSelect::~DeviceSelect(){
    delete ui;
};
