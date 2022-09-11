#include <Havoc/DBManager/DBManager.hpp>
#include <QFileInfo>

using namespace HavocNamespace::HavocSpace;

int DBManager::OpenSqlFile = 1;
int DBManager::CreateSqlFile = 2;

DBManager::DBManager( const QString& FilePath, int OpenFlag )
{
    bool dbExists = false;
    if ( QFileInfo::exists( FilePath ) )
        dbExists = true;

    this->DB = QSqlDatabase::addDatabase( "QSQLITE" );
    this->DB.setDatabaseName( FilePath );

    if ( this->DB.open() )
    {
        if ( OpenFlag == DBManager::CreateSqlFile && !dbExists )
        {
            if ( this->createNewDatabase() )
            {
                spdlog::info( "Successful created database" );
            }
            else
            {
                spdlog::error( "Failed to create a new database" );
            }
        }
    }
    else
    {
        spdlog::error( "[DB] Failed to open database" );
    }
}

bool DBManager::createNewDatabase()
{
    bool success = false;
    if ( DB.isOpen() )
    {
        auto query = QSqlQuery();

        // Teamserver
        query.prepare(
                "CREATE TABLE \"Teamservers\" ( "
                "\"ID\" INTEGER PRIMARY KEY, "
                "\"ProfileName\" TEXT, "
                "\"Host\" TEXT, "
                "\"Port\" INTEGER, "
                "\"User\" TEXT, "
                "\"Password\" TEXT "
                ");"
        );
        success = query.exec();
        if ( ! success )
            spdlog::error( "[DB] Couldn't create Teamserver table: ", query.lastError().text().toStdString() );

        // Sessions
        query.prepare(
                "CREATE TABLE \"Sessions\" ( "
                "\"ID\" INTEGER PRIMARY KEY, "
                "\"TeamserverID\" INTEGER, "
                "\"NameID\" TEXT, "
                "\"External\" TEXT, "
                "\"Internal\" TEXT, "
                "\"Listener\" TEXT, "
                "\"User\" TEXT, "
                "\"Computer\" TEXT, "
                "\"OS\" TEXT, "
                "\"Process\" TEXT, "
                "\"PID\" INTEGER, "
                "\"Arch\" TEXT, "
                "\"Last\" TEXT"
                ");"
        );
        success = query.exec();
        if ( ! success )
            spdlog::error( "[DB] Couldn't create Sessions table: ", query.lastError().text().toStdString() );

        // Listener
        query.prepare(
                "CREATE TABLE \"Listeners\" ( "
                "\"ID\" INTEGER PRIMARY KEY, "
                "\"TeamserverID\" INTEGER, "
                "\"Name\" TEXT, "
                "\"Protocol\" TEXT, "
                "\"Host\" TEXT, "
                "\"Port\" INTEGER, "
                "\"Connected\" INTEGER, "
                "\"Status\" TEXT"
                ");"
        );
        success = query.exec();
        if ( ! success )
            spdlog::error( "[DB] Couldn't create Listener table: ", query.lastError().text().toStdString() );

        // Credentials
        query.prepare(
                "CREATE TABLE \"Credentials\" ( "
                "\"ID\" INTEGER PRIMARY KEY, "
                "\"TeamserverID\" INTEGER, "
                "\"User\" TEXT, "
                "\"Password\" TEXT, "
                "\"Type\" TEXT, "
                "\"Domain\" TEXT, "
                "\"Source\" TEXT, "
                "\"Added\" TEXT "
                ");"
        );
        success = query.exec();
        if ( ! success )
            spdlog::error( "[DB] Couldn't create Credentials table: ", query.lastError().text().toStdString() );

        // Scripts
        query.prepare(
                "CREATE TABLE \"Scripts\" ( "
                "\"ID\" INTEGER PRIMARY KEY, "
                "\"Path\" TEXT "
                ");"
        );
        success = query.exec();
        if ( ! success )
            spdlog::error( "[DB] Couldn't create Scripts table: ", query.lastError().text().toStdString() );
    }
    return success;
}