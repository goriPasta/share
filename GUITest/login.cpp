#include "login.h"
#include "ui_login.h"

Login::Login(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Login)
{
    ui->setupUi(this);
    //this->setWindowFlags(Qt::CustomizeWindowHint|Qt::WindowTitleHint);

}


Login::~Login()
{
    delete ui;
}

bool Login::angou(){
    return false;
}
void Login::on_cancel_button_clicked()
{
    reject();
}

bool Login::LoginJudge(QString Usr,QString Pass){
    QString Name="tanaka";
    QString PWord="123456";
    QString PassJudge="false";
    QString True="true";
    /*connect to DB*/
    db = QSqlDatabase::addDatabase("QPSQL");
    db.setHostName("localhost");
    db.setDatabaseName("postgres");
    db.setUserName("postgres");
    //db.setPassword("postgres");
    bool ok = db.open();
    if(ok != true) QMessageBox::critical(this,"Connection","Connection Failed!");
    QSqlQuery query(db);
    if (query.prepare("select (password = crypt(?, password)) from user_data where name=?")) {
        query.addBindValue(Pass);
        query.addBindValue(Usr);
        if (query.exec()) {
            while (query.next()) {
                PassJudge = query.value(0).toString();
            }
        } else {
            qWarning() << query.lastError();
            qInfo() << query.lastQuery() << query.boundValues();
        }
    } else {
        qWarning() << query.lastError();
    }
    db.close();
    if(PassJudge.toUtf8().data() == True){
        return true;
    }
    else {
        QMessageBox::critical(this,"","不正なログインです");
        return false;
    }
}

void Login::on_login_button_clicked()
{
    QString UN=ui->lineEdit_username->text();
    QString PW=ui->lineEdit_password->text();
    if(UN.isEmpty() or PW.isEmpty()) QMessageBox::critical(this,"","入力されていません");
    else if(LoginJudge(UN,PW)==true){
        accept();
    }
}

void Login::on_register_button_clicked()
{
    QString UN=ui->lineEdit_username->text();
    QString PW=ui->lineEdit_password->text();
    if(UN.isEmpty() or PW.isEmpty()) QMessageBox::critical(this,"","入力されていません");
    else {
        /*connect to DB*/
        db = QSqlDatabase::addDatabase("QPSQL");
        db.setHostName("localhost");
        db.setDatabaseName("postgres");
        db.setUserName("postgres");
        //db.setPassword("postgres");
        bool ok = db.open();
        if(ok != true) QMessageBox::critical(this,"Connection","Connection Failed!");
        QSqlQuery query(db);
        if (query.exec("create table user_data(name text primary key not null, password text not null)")) {
            if (!query.exec()) {
                qWarning() << query.lastError();
                qInfo() << query.lastQuery() << query.boundValues();
            }
        } else {
            qWarning() << query.lastError();
        }
        if (query.prepare("insert into user_data(name, password) values (?,(crypt(?,gen_salt('md5'))))")) {
            query.addBindValue(UN);
            query.addBindValue(PW);
            if (query.exec()) {
                qInfo() << query.lastInsertId().toLongLong() << "added";
                QMessageBox::information(this,"","ユーザを登録しました");
            } else {
                qWarning() <<query.lastError();
                qInfo() << query.lastQuery() << query.boundValues();
                QMessageBox::critical(this,"","ユーザ名がすでに使われています");
            }
        } else {
            qWarning() << query.lastError();
        }
        db.close();
    }
}
