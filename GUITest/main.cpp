#include "widget.h"
#include "deviceselect.h"
#include "mainwindow.h"
#include "login.h"
#include <QApplication>
#include <QTimer>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    //Widget w;
    QCoreApplication::setApplicationName("CAPCAP");
    MainWindow mw;
    //QTimer::singleShot(0,select);
    Login l;
    DeviceSelect ds;
    if(l.exec()){
        if(ds.exec()){
            QString na=ds.comb->currentText();
            if(ds.chek[0]->checkState()==Qt::Checked)mw.getTCP();
            if(ds.chek[1]->checkState()==Qt::Checked)mw.getUDP();
            if(ds.chek[2]->checkState()==Qt::Checked)mw.getDNS();
            if(mw.zikkoutyu==false){
                std::string name=na.toStdString();
                mw.m.add_pcapdev(name);
                mw.m.start();
                mw.et.start();
                mw.zikkoutyu=true;
            }
            mw.show();
        }
    }

    return a.exec();
}

