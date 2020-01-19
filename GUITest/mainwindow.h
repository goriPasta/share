#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QWidget>
#include <packetmachine.hpp>
#include <string>
//#include "listmodel.h"
#include "packetlistmodel.h"
#include "deviceselect.h"
#include<pcap.h>
#include <sstream>
#include <QElapsedTimer>
#include <QtSql/QSqlDatabase>
#include <QtSql/QSqlQuery>
#include <QtSql/QSqlError>
#include <QDebug>
#include <QMessageBox>
namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    pm::Machine m;
    QSqlDatabase db;
    QElapsedTimer et;
    QElapsedTimer et2;
    bool zikkoutyu;
    unsigned long int counter;
    void getTCP();
    void getUDP();
    void getDNS();
    void getARP();
    void getICMP();
    void getDHCP();
    ListModel* getModel();


  public slots:

  private slots:
    void select();
    //!toolbar
    void newFile();
    void open();
    void save();
    void print();
    void about();
    void aboutQt();
    //void find();
    //void preference();
    //void search();
//    void filter_bar();
    void start();
    void stop();
    void restart();
    void graph_plot();
    //! toolbar end

    //! click_action
    //void on_pushButton_clicked();
    void on_pushButton_2_clicked();
    void database_connection();
    //! click_action end

private:

    void createActions();
    void createMenu();
    void createToolBar();
    MainWindow *findMainWindow(const QString &fileName) const;


    Ui::MainWindow *ui;
    DeviceSelect *ds;
    ListModel *model;
    //!Menu
    QMenu *fileMenu;//fail menu
    QMenu *editMenu;//edit menu
    QMenu *viewMenu;//view menu
    QMenu *moveMenu;//move menu
    QMenu *capMenu;//capture menu
    QMenu *analyMenu;//analysis menu
    QMenu *statisMenu;//statistics menu
    QMenu *formatMenu;
    QMenu *helpMenu;
    //!Menu end
    //! ToolBar
    QToolBar *ToolBar;
    //! ToolBar end
    QActionGroup *alignmentGroup;

    //! menu action
    QAction *newAct,*openAct,*saveAct,*printAct,*exitAct;//fail Menu
    QAction *findAct,*findNextAct,*findPrevAct,*preferenceAct;//edit Menu
    QAction *dispToolbar,*dispFilterBar;//view Menu
    QAction *nextPac,*prevPac,*firstPac,*endPac;//move Menu
    QAction *startCap,*stopCap,*restartCap;//capture Menu
    QAction *filter,*track;//analysis Menu
    QAction *graph;//statistics Menu
    QAction *aboutAct,*aboutQtAct;//about Menu
    QLabel *infoLabel;//assist label
    //!menu action end
};

#endif // MAINWINDOW_H
