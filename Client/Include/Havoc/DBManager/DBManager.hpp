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
    // TODO: create for each of them a functions

    // Teamserver
    bool addTeamserverInfo( Util::ConnectionInfo );
    bool checkTeamserverExists( const QString& ProfileName );
    bool removeTeamserverInfo( const QString& ProfileName );
    bool removeAllTeamservers();
    vector<Util::ConnectionInfo> listTeamservers();

    // Sessions
    bool addSession( const QString& TeamserverID, Util::SessionItem );
    bool removeSession( const QString& TeamserverID, const QString& DemonSessionID );
    bool changeSessionID( const QString& TeamserverID, Util::SessionItem* Session );
    vector<Util::SessionItem> listSessions();

    // Credentials
    bool addCredentials( Util::CredentialsItem );
    void editCredentials( Util::CredentialsItem* );
    bool removeCredentials( int CredentialsID );
    vector<Util::CredentialsItem> listCredentials();

    bool AddScript( QString Path );
    bool RemoveScript( QString Path );
    bool CheckScript( QString Path );
    vector<QString> GetScripts();

};

#endif