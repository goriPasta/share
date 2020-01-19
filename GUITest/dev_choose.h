#ifndef DEV_CHOOSE_H
#define DEV_CHOOSE_H
#include <QWidget>
#include <packetmachine.hpp>
#include <QString>
#include <QAbstractListModel>
#include <QVector>
#include <iostream>
#include <vector>
#include <packetmachine.hpp>
#include <pcap.h>
#include <unistd.h>
#include <stdio.h>
#include <string>
#include <sstream>


class Packett{
    public:
    std::string event;
    //const pm::Property& p;
    std::string sourceip;
    std::string destip;
    std::string size;

    /*public:
    std::string getEvent(){
        return event;
    }*/

    /*Packett(std::string eventv,const pm::Property& pv):p(pv){
        event=eventv;
    }*/
    Packett(std::string eventv,std::string sourceipv,std::string destipv,std::string sizev){
        event=eventv;
        sourceip=sourceipv;
        destip=destipv;
        size=sizev;
    }
};

#endif // DEV_CHOOSE_H
