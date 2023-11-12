#ifndef HAVOC_DBMANAGER_HPP
#define HAVOC_DBMANAGER_HPP

#include <global.hpp>

#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>

using namespace std;

class HavocNamespace::HavocSpace::DBManager
{
private:
    QSqlDatabase DB;

    bool createNewDatabase();

public:
    static string DBFilePath;

    static int OpenSqlFile;
    static int CreateSqlFile;

    DBManager(const QString& FilePath, int OpenFlag = OpenSqlFile);

    bool addTeamserverInfo( const Util::ConnectionInfo& );
    bool checkTeamserverExists( const QString& ProfileName );
    bool removeTeamserverInfo( const QString& ProfileName );
    bool removeAllTeamservers();
    vector<Util::ConnectionInfo> listTeamservers();

    bool AddScript( QString Path );
    bool RemoveScript( QString Path );
    bool CheckScript( QString Path );
    vector<QString> GetScripts();
};

#endif