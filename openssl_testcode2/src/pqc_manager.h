#ifndef PQC_MANAGER_H
#define PQC_MANAGER_H

#include <QObject>
#include <QString>

class PQCManager : public QObject
{
    Q_OBJECT

public:
    explicit PQCManager(QObject *parent = nullptr);

    // Add this new function declaration 👇
    void runRole(const QString &role, const QString &algo);
};

#endif // PQC_MANAGER_H
