#ifndef DEVICESELECT_H
#define DEVICESELECT_H

#include <QDialog>
#include <QComboBox>
#include <QCheckBox>
#include <QtGui>
#include <QtWidgets>
#include <QFormLayout>

namespace Ui {
class DeviceSelect;
}

class DeviceSelect : public QDialog
{
    Q_OBJECT

public:
    explicit DeviceSelect(QWidget *parent = nullptr);
    ~DeviceSelect();
    QFormLayout *BL;
    QComboBox *comb;
    QCheckBox *chek[7];
/*signals:
    void devSignal(QString);

public slots:
    void emitdevSignal(QString);
private slots:
*/

private:
    Ui::DeviceSelect *ui;
};

#endif // DEVICESELECT_H
