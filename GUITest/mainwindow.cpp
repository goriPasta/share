#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "login.h"
#include "chart.h"
#include <QtWidgets/QApplication>
#include <QtWidgets/QMainWindow>
#include <QtCharts/QChartView>
#include <QtCharts/QLineSeries>


QT_CHARTS_USE_NAMESPACE

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    model = new ListModel();
    ui->tableView->setModel(model);
    zikkoutyu=false;
    this->setVisible(false);
    createActions();
    createMenu();
    createToolBar();
    //et.start();
    counter=0;
}

MainWindow::~MainWindow()
{
    delete ui;
    delete model;
    delete ds;
}
void MainWindow::select(){
    DeviceSelect dev(this);
    if(dev.exec()){
        QString na=dev.comb->currentText();
        if(dev.chek[0]->checkState()==Qt::Checked)getTCP();
        if(dev.chek[1]->checkState()==Qt::Checked)getUDP();
        if(dev.chek[2]->checkState()==Qt::Checked)getDNS();
        if(dev.chek[3]->checkState()==Qt::Checked)getARP();
        if(dev.chek[4]->checkState()==Qt::Checked)getICMP();
        if(dev.chek[5]->checkState()==Qt::Checked)getDHCP();
        if(zikkoutyu==false){
            std::string name=na.toStdString();
            m.add_pcapdev(name);
            m.start();
            zikkoutyu=true;
        }
    }
}

//void MainWindow::on_pushButton_clicked()
//{
//   select();
//}
void MainWindow::database_connection(){
    char PSW[]="ono";
    std::ostringstream s1;
    std::ostringstream s2;
    std::ostringstream date;

    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    date << tm.tm_year+1900 << "_" << tm.tm_mon+1 << "_" << tm.tm_mday << "_" << tm.tm_hour << "_" << tm.tm_min << "_" << tm.tm_sec;
    s1 << "create table " << "packetcapture_" << date.str() << "(id serial primary key,time bytea,source bytea,destination bytea,length bytea,protocol bytea)";
    s2 << "insert into " << "packetcapture_" << date.str() << "(time,source,destination,length,protocol) values ((pgp_sym_encrypt(?,?)),(pgp_sym_encrypt(?,?)),(pgp_sym_encrypt(?,?)),(pgp_sym_encrypt(?,?)),(pgp_sym_encrypt(?,?)))";
    QString CreateTable=QString::fromStdString(s1.str());
    QString InsertDB=QString::fromStdString(s2.str());
    /*connect to DB*/
          db = QSqlDatabase::addDatabase("QPSQL");
          db.setHostName("localhost");
          db.setDatabaseName("testdb");
          db.setUserName("testuser");
          db.setPassword("kinako");
          bool ok = db.open();
          if(ok != true) QMessageBox::information(this,"Connection","Connection Failed!");
          else QMessageBox::information(this,"Connection","Connection OK!");

        QSqlQuery query(db);
        /*create table*/
        if (query.exec(CreateTable)){
            if (query.exec()) {
               qInfo() << query.lastInsertId().toLongLong() << "added";
            }
            else {
                qWarning() <<query.lastError();
                qInfo() << query.lastQuery() << query.boundValues();
            }
        }
        else {
            qWarning() << query.lastError();
        }
        /*insert into db*/
        //for (auto &num:model->list){//パケットクラス配列の内容の表示
        for(int i=0;i<model->getSizeofList();i++){
            if (query.prepare(InsertDB)){
                       //パケット取得(getPacket)->そのパケットのステータス配列取得(getstatusvector)->各要素アクセスという形でアクセスしています
                query.addBindValue(model->getPacket(i)->getStatusVector()[0]);//dates
                query.addBindValue(PSW);
                query.addBindValue(model->getPacket(i)->getStatusVector()[1]);//source
                query.addBindValue(PSW);
                query.addBindValue(model->getPacket(i)->getStatusVector()[2]);//dest
                query.addBindValue(PSW);
                query.addBindValue(model->getPacket(i)->getStatusVector()[3]);//length
                query.addBindValue(PSW);
                query.addBindValue(model->getPacket(i)->getStatusVector()[4]);//protocol
                query.addBindValue(PSW);
                /*query.addBindValue(num->source);
                query.addBindValue(num->dest);
                query.addBindValue(num->length);
                query.addBindValue(num->protocol);*/
                if (query.exec()) {
                   qInfo() << query.lastInsertId().toLongLong() << "added";
                }
                else {
                    qWarning() <<query.lastError();
                    qInfo() << query.lastQuery() << query.boundValues();
                }
            }
            else {
                qWarning() << query.lastError();
            }
        }
        db.close();
}

void MainWindow::on_pushButton_2_clicked()
{
    char PSW[]="ono";
    std::ostringstream s1;
    std::ostringstream s2;
    std::ostringstream date;

    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    date << tm.tm_year+1900 << "_" << tm.tm_mon+1 << "_" << tm.tm_mday << "_" << tm.tm_hour << "_" << tm.tm_min << "_" << tm.tm_sec;
    s1 << "create table " << "packetcapture_" << date.str() << "(id serial primary key,dates bytea,source bytea,destination bytea,length bytea,protocol bytea)";
    s2 << "insert into " << "packetcapture_" << date.str() << "(dates,source,destination,length,protocol) values ((pgp_sym_encrypt(?,?)),(pgp_sym_encrypt(?,?)),(pgp_sym_encrypt(?,?)),(pgp_sym_encrypt(?,?)),(pgp_sym_encrypt(?,?)))";
    QString CreateTable=QString::fromStdString(s1.str());
    QString InsertDB=QString::fromStdString(s2.str());
    /*connect to DB*/
          db = QSqlDatabase::addDatabase("QPSQL");
          db.setHostName("localhost");
          db.setDatabaseName("testdb");
          db.setUserName("testuser");
          db.setPassword("kinako");
          bool ok = db.open();
          if(ok != true) QMessageBox::information(this,"Connection","Connection Failed!");
          else QMessageBox::information(this,"Connection","Connection OK!");

        QSqlQuery query(db);
        /*create table*/
        if (query.exec(CreateTable)){
            if (query.exec()) {
               qInfo() << query.lastInsertId().toLongLong() << "added";
            }
            else {
                qWarning() <<query.lastError();
                qInfo() << query.lastQuery() << query.boundValues();
            }
        }
        else {
            qWarning() << query.lastError();
        }
        /*insert into db*/
        //for (auto &num:model->list){//パケットクラス配列の内容の表示
        for(int i=0;i<model->getSizeofList();i++){
            if (query.prepare(InsertDB)){
                       //パケット取得(getPacket)->そのパケットのステータス配列取得(getstatusvector)->各要素アクセスという形でアクセスしています
                query.addBindValue(model->getPacket(i)->getStatusVector()[0]);//time
                query.addBindValue(PSW);
                query.addBindValue(model->getPacket(i)->getStatusVector()[1]);//source
                query.addBindValue(PSW);
                query.addBindValue(model->getPacket(i)->getStatusVector()[2]);//dest
                query.addBindValue(PSW);
                query.addBindValue(model->getPacket(i)->getStatusVector()[3]);//length
                query.addBindValue(PSW);
                query.addBindValue(model->getPacket(i)->getStatusVector()[4]);//protocol
                query.addBindValue(PSW);
                /*query.addBindValue(num->source);
                query.addBindValue(num->dest);
                query.addBindValue(num->length);
                query.addBindValue(num->protocol);*/
                if (query.exec()) {
                   qInfo() << query.lastInsertId().toLongLong() << "added";
                }
                else {
                    qWarning() <<query.lastError();
                    qInfo() << query.lastQuery() << query.boundValues();
                }
            }
            else {
                qWarning() << query.lastError();
            }
        }
        //model->clearList();
        ui->tableView->reset();
        model = new ListModel();
        ui->tableView->setModel(model);
        db.close();

}
ListModel* MainWindow::getModel(){
    return this->model;
}
void MainWindow::getTCP(){
    m.on("TCP", [&](const pm::Property& p) {    //イベント "UDP"のコールバック関数
        const auto& s3=p.pkt_size();
        std::ostringstream s1;
        std::ostringstream s2;
        //double time=(et.elapsed())/(double)1000;

        QElapsedTimer timer;
        timer.start();

        time_t now = time(NULL);
        struct tm tm;
        localtime_r(&now, &tm);
        std::ostringstream date;
        date << tm.tm_year+1900 << "_" << tm.tm_mon+1 << "_" << tm.tm_mday << "_" << tm.tm_hour << "_" << tm.tm_min << "_" << tm.tm_sec;
        const std::string dates=date.str();

        //qDebug() << time;
        counter += 1;
        const std::string ss3=std::to_string(s3);
            //ストリームにパケットの情報を書きこむ
        s1<<p["IPv4.src"];
        s2<<p["IPv4.dst"];
        const std::string ss1=s1.str();
        const std::string ss2=s2.str();
        model->add(new Packet(counter,tr(dates.c_str()),tr(ss1.c_str()),tr(ss2.c_str()),
                tr("TCP"),tr(ss3.c_str())));
        ui->tableView->scrollToBottom();
     });
}
void MainWindow::getUDP(){
    m.on("UDP", [&](const pm::Property& p) {    //イベント "UDP"のコールバック関数
        const auto& s3=p.pkt_size();
        std::ostringstream s1;
        std::ostringstream s2;

        QElapsedTimer timer;
        timer.start();

        time_t now = time(NULL);
        struct tm tm;
        localtime_r(&now, &tm);
        std::ostringstream date;
        date << tm.tm_year+1900 << "_" << tm.tm_mon+1 << "_" << tm.tm_mday << "_" << tm.tm_hour << "_" << tm.tm_min << "_" << tm.tm_sec;
        const std::string dates=date.str();

        //double time=(et.elapsed())/(double)1000;
        counter+=1;
        const std::string ss3=std::to_string(s3);
            //ストリームにパケットの情報を書きこむ
        s1<<p["IPv4.src"];
        s2<<p["IPv4.dst"];
        const std::string ss1=s1.str();
        const std::string ss2=s2.str();
        model->add(new Packet(counter,tr(dates.c_str()),tr(ss1.c_str()),tr(ss2.c_str()),
                tr("UDP"),tr(ss3.c_str())));
        ui->tableView->scrollToBottom();
     });
}
void MainWindow::getDNS(){
    m.on("DNS", [&](const pm::Property& p) {    //イベント "UDP"のコールバック関数
        const auto& s3=p.pkt_size();
        std::ostringstream s1;
        std::ostringstream s2;

        QElapsedTimer timer;
        timer.start();
        time_t now = time(NULL);
        struct tm tm;
        localtime_r(&now, &tm);
        std::ostringstream date;
        date << tm.tm_year+1900 << "_" << tm.tm_mon+1 << "_" << tm.tm_mday << "_" << tm.tm_hour << "_" << tm.tm_min << "_" << tm.tm_sec;
        const std::string dates=date.str();

        //double time=(et.elapsed())/(double)1000;
        counter+=1;
        const std::string ss3=std::to_string(s3);
            //ストリームにパケットの情報を書きこむ
        s1<<p["IPv4.src"];
        s2<<p["IPv4.dst"];
        const std::string ss1=s1.str();
        const std::string ss2=s2.str();
        model->add(new Packet(counter,tr(dates.c_str()),tr(ss1.c_str()),tr(ss2.c_str()),
                tr("DNS"),tr(ss3.c_str())));
        ui->tableView->scrollToBottom();
     });
}

void MainWindow::getARP(){
    m.on("ARP", [&](const pm::Property& p) {    //イベント "UDP"のコールバック関数
        const auto& s3=p.pkt_size();
        std::ostringstream s1;
        std::ostringstream s2;

        //QElapsedTimer timer;
        //timer.start();
        time_t now = time(NULL);
        struct tm tm;
        localtime_r(&now, &tm);
        std::ostringstream date;
        date << tm.tm_year+1900 << "_" << tm.tm_mon+1 << "_" << tm.tm_mday << "_" << tm.tm_hour << "_" << tm.tm_min << "_" << tm.tm_sec;
        const std::string dates=date.str();

        //double time=(et.elapsed())/(double)1000;
        counter+=1;
        const std::string ss3=std::to_string(s3);
            //ストリームにパケットの情報を書きこむ
        s1<<p["IPv4.src"];
        s2<<p["IPv4.dst"];
        const std::string ss1=s1.str();
        const std::string ss2=s2.str();
        model->add(new Packet(counter,tr(dates.c_str()),tr(ss1.c_str()),tr(ss2.c_str()),
                tr("ARP"),tr(ss3.c_str())));
        ui->tableView->scrollToBottom();
     });
}

void MainWindow::getICMP(){
    m.on("ICMP", [&](const pm::Property& p) {    //イベント "UDP"のコールバック関数
        const auto& s3=p.pkt_size();
        std::ostringstream s1;
        std::ostringstream s2;

        //QElapsedTimer timer;
        //timer.start();
        time_t now = time(NULL);
        struct tm tm;
        localtime_r(&now, &tm);
        std::ostringstream date;
        date << tm.tm_year+1900 << "_" << tm.tm_mon+1 << "_" << tm.tm_mday << "_" << tm.tm_hour << "_" << tm.tm_min << "_" << tm.tm_sec;
        const std::string dates=date.str();

        //double time=(et.elapsed())/(double)1000;
        counter+=1;
        const std::string ss3=std::to_string(s3);
            //ストリームにパケットの情報を書きこむ
        s1<<p["IPv4.src"];
        s2<<p["IPv4.dst"];
        const std::string ss1=s1.str();
        const std::string ss2=s2.str();
        model->add(new Packet(counter,tr(dates.c_str()),tr(ss1.c_str()),tr(ss2.c_str()),
                tr("ICMP"),tr(ss3.c_str())));
        ui->tableView->scrollToBottom();
     });
}

/*void MainWindow::getmDNS(){
    m.on("mDNS", [&](const pm::Property& p) {    //イベント "UDP"のコールバック関数
        const auto& s3=p.pkt_size();
        std::ostringstream s1;
        std::ostringstream s2;

        //QElapsedTimer timer;
        //timer.start();
        double time=(et.elapsed())/1000;
        counter+=1;
        const std::string ss3=std::to_string(s3);
            //ストリームにパケットの情報を書きこむ
        s1<<p["IPv4.src"];
        s2<<p["IPv4.dst"];
        const std::string ss1=s1.str();
        const std::string ss2=s2.str();
        model->add(new Packet(counter,time,tr(ss1.c_str()),tr(ss2.c_str()),
                tr("mDNS"),tr(ss3.c_str())));
        ui->tableView->scrollToBottom();
     });
}*/
void MainWindow::getDHCP(){
    m.on("DHCP", [&](const pm::Property& p) {    //イベント "UDP"のコールバック関数
        const auto& s3=p.pkt_size();
        std::ostringstream s1;
        std::ostringstream s2;

        //QElapsedTimer timer;
        //timer.start();
        time_t now = time(NULL);
        struct tm tm;
        localtime_r(&now, &tm);
        std::ostringstream date;
        date << tm.tm_year+1900 << "_" << tm.tm_mon+1 << "_" << tm.tm_mday << "_" << tm.tm_hour << "_" << tm.tm_min << "_" << tm.tm_sec;
        const std::string dates=date.str();

        //double time=(et.elapsed())/(double)1000;
        counter+=1;
        const std::string ss3=std::to_string(s3);
            //ストリームにパケットの情報を書きこむ
        s1<<p["IPv4.src"];
        s2<<p["IPv4.dst"];
        const std::string ss1=s1.str();
        const std::string ss2=s2.str();
        model->add(new Packet(counter,tr(dates.c_str()),tr(ss1.c_str()),tr(ss2.c_str()),
                tr("DHCP"),tr(ss3.c_str())));
        ui->tableView->scrollToBottom();
     });
}

void MainWindow::newFile()
{
    QFileDialog fileDialog(this);
    fileDialog.setFileMode(QFileDialog::Directory);
    fileDialog.setOption(QFileDialog::ShowDirsOnly,true);
    if(fileDialog.exec()){
        QStringList filePath=fileDialog.selectedFiles();
    }
}

void MainWindow::open()
{
    QString fileName=QFileDialog::getOpenFileName(this,tr("Open File"),"",
                                                  tr("Text Files(*.txt);;C++ Files (*.cpp*.h)"));
    if(fileName.isEmpty()){
        QFile file(fileName);
        if(!file.open(QIODevice::ReadOnly)){
            QMessageBox::critical(this,tr("Error"),tr("Cloud not open file"));
            return;
        }
        QTextStream in(&file);
        file.close();
    }

}


void MainWindow::save()
{
    QString fileName=QFileDialog::getSaveFileName(this,tr("Open File"),"",
                                                  tr("Text Files(*.txt);;C++ Files (*.cpp*.h)"));
    if(!fileName.isEmpty()){
        QFile file(fileName);
        if(!file.open(QIODevice::WriteOnly)){
            //errormessage
        }else{
            QTextStream stream(&file);
            file.close();
        }
    }
}

void MainWindow::print()
{
}
void MainWindow::start(){
    QMessageBox msgBox(this);
    msgBox.setWindowTitle(tr("Unsaved packets"));
    msgBox.setText(tr("Do you save captured packets or not?\n"
                      "If you don't save that, lose captured data."));
    msgBox.setStandardButtons(QMessageBox::Yes|QMessageBox::No|QMessageBox::Cancel);
    msgBox.setDefaultButton(QMessageBox::Yes);
    msgBox.setButtonText(QMessageBox::Yes,tr("Save"));
    msgBox.setButtonText(QMessageBox::No,tr("Discard"));
    msgBox.setButtonText(QMessageBox::Cancel,tr("Cancel"));
    int res=msgBox.exec();
    if(res==QMessageBox::Yes){
        database_connection();
        ui->tableView->reset();
        model = new ListModel();
        ui->tableView->setModel(model);
        m.start();
        counter=0;
        et.restart();
        zikkoutyu=true;
    }
    else if (res==QMessageBox::No){
        ui->tableView->reset();
        model = new ListModel();
        ui->tableView->setModel(model);
        m.start();
        counter=0;
        et.restart();
        zikkoutyu=true;
    }
    else{
        msgBox.close();
    }

}
void MainWindow::stop(){
    m.halt();
}
void MainWindow::restart(){
    QMessageBox msgBox(this);
    msgBox.setWindowTitle(tr("Unsaved packets"));
    msgBox.setText(tr("Do you save captured packets or not?\n"
                      "If you don't save that, lose captured data."));
    msgBox.setStandardButtons(QMessageBox::Yes|QMessageBox::No|QMessageBox::Cancel);
    msgBox.setDefaultButton(QMessageBox::Yes);
    msgBox.setButtonText(QMessageBox::Yes,tr("Save"));
    msgBox.setButtonText(QMessageBox::No,tr("Discard"));
    msgBox.setButtonText(QMessageBox::Cancel,tr("Cancel"));
    int res=msgBox.exec();
    if(res==QMessageBox::Yes){
        database_connection();
        ui->tableView->reset();
        model = new ListModel();
        ui->tableView->setModel(model);
        m.start();
        counter=0;
        et.restart();
        zikkoutyu=true;
    }
    else if (res==QMessageBox::No){
        ui->tableView->reset();
        model = new ListModel();
        ui->tableView->setModel(model);
        m.start();
        counter=0;
        et.restart();
        zikkoutyu=true;
    }
    else{
        msgBox.close();
    }

}

void MainWindow::graph_plot(){
    et2.start();
    Chart *chart = new Chart;
    chart->setTitle("Dynamic spline chart");
    chart->legend()->hide();

    chart->setAnimationOptions(QChart::AnimationOption::SeriesAnimations);
    chart->mw=this;


    QChartView *chartView = new QChartView(chart);
    chartView->setRenderHint(QPainter::Antialiasing);

     ui->verticalLayout_2->addWidget(chartView);
}
void MainWindow::about()
{
    infoLabel->setText(tr("Invoked <b>Help|About</b>"));
    QMessageBox::about(this, tr("About Menu"),
            tr("The <b>Menu</b> example shows how to create "
               "menu-bar menus and context menus."));
}

MainWindow *MainWindow::findMainWindow(const QString &fileName) const
{
    QString canonicalFilePath=QFileInfo(fileName).canonicalFilePath();
    foreach(QWidget *widget,QApplication::topLevelWidgets()){
        MainWindow *mainWin=qobject_cast<MainWindow *>(widget);
        return mainWin;
    }
    return 0;
}

void MainWindow::aboutQt()
{
    infoLabel->setText(tr("Invoked <b>Help|About Qt</b>"));
}

void MainWindow::createActions()
{
    newAct = new QAction(tr("&New"), this);
    newAct->setShortcuts(QKeySequence::New);
    newAct->setStatusTip(tr("Create a new file"));
    connect(newAct, &QAction::triggered, this, &MainWindow::newFile);

    openAct = new QAction(tr("&Open..."), this);
    openAct->setShortcuts(QKeySequence::Open);
    openAct->setStatusTip(tr("Open an existing file"));
    connect(openAct, &QAction::triggered, this, &MainWindow::open);

    saveAct = new QAction(tr("&Save"), this);
    saveAct->setShortcuts(QKeySequence::Save);
    saveAct->setStatusTip(tr("Save the document to disk"));
    connect(saveAct, &QAction::triggered, this, &MainWindow::save);

    printAct = new QAction(tr("&Print..."), this);
    printAct->setShortcuts(QKeySequence::Print);
    printAct->setStatusTip(tr("Print the document"));
    connect(printAct, &QAction::triggered, this, &MainWindow::print);

    exitAct = new QAction(tr("&Exit"), this);
    exitAct->setShortcuts(QKeySequence::Quit);
    exitAct->setStatusTip(tr("Exit the application"));
    connect(exitAct, &QAction::triggered, this, &QWidget::close);

    findAct=new QAction(tr("Search Packets"),this);
    findAct->setShortcut(QKeySequence::Find);
    findAct->setStatusTip(tr("Search Packets"));
    //connect(findAct,&QAction::triggered,this,&MainWindow::search);

    findNextAct=new QAction(tr("Search Packets"),this);
    findNextAct->setShortcut(QKeySequence::FindNext);
    findNextAct->setStatusTip(tr("Search Next Packets"));
    //connect(findAct,&QAction::triggered,this,&MainWindow::search);

    findPrevAct=new QAction(tr("Search Packets"),this);
    findPrevAct->setShortcut(QKeySequence::FindPrevious);
    findPrevAct->setStatusTip(tr("Search Previous Packets"));
    //connect(findAct,&QAction::triggered,this,&MainWindow::search);

    preferenceAct=new QAction(tr("Preference"),this);
    preferenceAct->setShortcut(QKeySequence::Preferences);
    preferenceAct->setStatusTip(tr("Preference"));
    //connect(findAct,&QAction::triggered,this,&MainWindow::search);

    dispToolbar=new QAction(tr("Display ToolBar"),this);
    //dispToolbar->setShortcut(QKeySequence::FindPrevious);
    dispToolbar->setStatusTip(tr("Display ToolBar"));
    //connect(findAct,&QAction::triggered,this,&MainWindow::search);

    dispFilterBar=new QAction(tr("Display FilterBar"),this);
    //dispFilterBar->setShortcut(QKeySequence::FindPrevious);
    dispFilterBar->setStatusTip(tr("Display FilterBar"));
    //connect(findAct,&QAction::triggered,this,&MainWindow::search);

    nextPac=new QAction(tr("Next Packet"),this);
    //findPrevAct->setShortcut(QKeySequence::FindPrevious);
    nextPac->setStatusTip(tr("Next Packet"));
    //connect(findAct,&QAction::triggered,this,&MainWindow::search);

    prevPac=new QAction(tr("Previous Packet"),this);
    //findPrevAct->setShortcut(QKeySequence::FindPrevious);
    prevPac->setStatusTip(tr("Previous Packet"));
    //connect(findAct,&QAction::triggered,this,&MainWindow::search);

    firstPac=new QAction(tr("First Packet"),this);
    //findPrevAct->setShortcut(QKeySequence::FindPrevious);
    firstPac->setStatusTip(tr("First Packet"));
    //connect(findAct,&QAction::triggered,this,&MainWindow::search);

    endPac=new QAction(tr("End Packet"),this);
    //findPrevAct->setShortcut(QKeySequence::FindPrevious);
    endPac->setStatusTip(tr("End Packet"));
    //connect(findAct,&QAction::triggered,this,&MainWindow::search);

    startCap=new QAction(tr("Start Capturing"),this);
    //startCap->setShortcut(QKeySequence::FindPrevious);
    startCap->setStatusTip(tr("Start Capturing"));
    connect(startCap,&QAction::triggered,this,&MainWindow::start);

    stopCap=new QAction(tr("Stop Capturing"),this);
    //stopCap->setShortcut(QKeySequence::FindPrevious);
    stopCap->setStatusTip(tr("Stop Captuering"));
    connect(stopCap,&QAction::triggered,this,&MainWindow::stop);

    restartCap=new QAction(tr("Restart Capturing"),this);
    //findPrevAct->setShortcut(QKeySequence::FindPrevious);
    restartCap->setStatusTip(tr("Restart Capturing"));
    connect(restartCap,&QAction::triggered,this,&MainWindow::restart);

    filter=new QAction(tr("Filtering Packets"),this);
    filter->setShortcut(QKeySequence::FindPrevious);
    filter->setStatusTip(tr("Filtering Packets"));
    //connect(findAct,&QAction::triggered,this,&MainWindow::search);

    track=new QAction(tr("Prack Packet"),this);
    //track->setShortcut(QKeySequence::FindPrevious);
    track->setStatusTip(tr("Track Packets"));
    //connect(findAct,&QAction::triggered,this,&MainWindow::search);

    graph=new QAction(tr("Show Graph"),this);
    //graph->setShortcut(QKeySequence::FindPrevious);
    graph->setStatusTip(tr("Show Graph"));
    connect(graph,&QAction::triggered,this,&MainWindow::graph_plot);

    aboutAct = new QAction(tr("&About"), this);
    aboutAct->setStatusTip(tr("Show the application's About box"));
    connect(aboutAct, &QAction::triggered, this, &MainWindow::about);

    aboutQtAct = new QAction(tr("About &Qt"), this);
    aboutQtAct->setStatusTip(tr("Show the Qt library's About box"));
    connect(aboutQtAct, &QAction::triggered, qApp, &QApplication::aboutQt);
    connect(aboutQtAct, &QAction::triggered, this, &MainWindow::aboutQt);
}

void MainWindow::createMenu()
{
    fileMenu = menuBar()->addMenu(tr("&File"));
    fileMenu->addAction(newAct);
    fileMenu->addAction(openAct);
    fileMenu->addAction(saveAct);
    fileMenu->addAction(printAct);
    fileMenu->addSeparator();
    fileMenu->addAction(exitAct);

    editMenu = menuBar()->addMenu(tr("&Edit"));
    editMenu->addAction(findAct);
    editMenu->addAction(findNextAct);
    editMenu->addAction(findPrevAct);
    editMenu->addSeparator();
    editMenu->addAction(preferenceAct);

    viewMenu = menuBar()->addMenu(tr("&View"));
    viewMenu->addAction(dispToolbar);
    viewMenu->addAction(dispFilterBar);

    moveMenu = menuBar()->addMenu(tr("&Move"));
    moveMenu->addAction(nextPac);
    moveMenu->addAction(prevPac);
    moveMenu->addAction(firstPac);
    moveMenu->addAction(endPac);

    capMenu = menuBar()->addMenu(tr("&Capture"));
    capMenu->addAction(startCap);
    capMenu->addAction(stopCap);
    capMenu->addAction(restartCap);

    analyMenu =menuBar()->addMenu(tr("&Analysis"));
    analyMenu->addAction(filter);
    analyMenu->addAction(track);

    statisMenu = menuBar()->addMenu(tr("&Statistics"));
    statisMenu->addAction(graph);

    helpMenu = menuBar()->addMenu(tr("&Help"));
    helpMenu->addAction(aboutAct);
    helpMenu->addAction(aboutQtAct);
//! [8]

//! [12]
    formatMenu = editMenu->addMenu(tr("&Format"));
    formatMenu->addSeparator()->setText(tr("Alignment"));
    formatMenu->addSeparator();
}

void MainWindow::createToolBar(){
    ToolBar = addToolBar(tr("&ToolBar"));
    ToolBar->addAction(startCap);
    ToolBar->addAction(stopCap);
    ToolBar->addAction(restartCap);
    //ToolBar->addAction();
    ToolBar->addAction(graph);
}
