#ifndef LOGIN_H
#define LOGIN_H

#include <QDialog>
#include <QtSql/QSqlDatabase>
#include <QtSql/QSqlQuery>
#include <QtSql/QSqlError>
#include <QDebug>
#include <QMessageBox>
#include <sstream>
#include <iostream>

namespace Ui {
class Login;
}

class Login : public QDialog
{
    Q_OBJECT

public:
    explicit Login(QWidget *parent = nullptr);
    ~Login();
    QSqlDatabase db;
    bool angou();

private slots:
    void on_cancel_button_clicked();

    void on_login_button_clicked();

    void on_register_button_clicked();

private:
    Ui::Login *ui;
    bool LoginJudge(QString User,QString Pass);
};

#endif // LOGIN_H
