#include <Havoc/DBManager/DBManager.hpp>
#include <QSqlError>

using namespace HavocNamespace;

bool HavocSpace::DBManager::addTeamserverInfo( const Util::ConnectionInfo& connection )
{
    auto query   = QSqlQuery();
    auto success = true;

    query.prepare( "insert into Teamservers (ProfileName, Host, Port, User, Password) values(:ProfileName, :Host, :Port, :User, :Password)" );

    query.bindValue( ":ProfileName", connection.Name.toStdString().c_str() );
    query.bindValue( ":Host",        connection.Host.toStdString().c_str() );
    query.bindValue( ":Port",        connection.Port.toStdString().c_str() );
    query.bindValue( ":User",        connection.User.toStdString().c_str() );
    query.bindValue( ":Password",    connection.Password.toStdString().c_str() );

    /* print error */
    if ( ! ( success = query.exec() ) ) {
        spdlog::error( "[DB] Failed to add teamserver info: {}", query.lastError().text().toStdString() );
        success = false;
    }

    return success;
}

bool HavocSpace::DBManager::checkTeamserverExists( const QString& ProfileName )
{
    auto query   = QSqlQuery();
    auto success = false;

    query.prepare( "select * from Teamservers" );

    if ( ! query.exec() ) {
        spdlog::error( "[DB] Failed to query teamserver existence: {}", query.lastError().text().toStdString() );
        return success;
    }

    while ( query.next() ) {
        if ( query.value( "ProfileName" ) == ProfileName ) {
            success = true;
            break;
        }
    }

    return success;
}

bool HavocSpace::DBManager::removeTeamserverInfo( const QString& ProfileName )
{
    auto query = QSqlQuery();

    query.prepare( "delete from Teamservers where ProfileName = :ProfileName" );
    query.bindValue( ":ProfileName", ProfileName );

    if ( ! query.exec() ) {
        spdlog::error( "[DB] Failed to deleting teamserver [{}] info: {}", ProfileName.toStdString(), query.lastError().text().toStdString() );
        return false;
    }

    return true;
}

vector<Util::ConnectionInfo> HavocSpace::DBManager::listTeamservers()
{
    auto query          = QSqlQuery();
    auto TeamserverList = vector<Util::ConnectionInfo>();

    query.prepare( "select * from Teamservers" );

    if ( ! query.exec() ) {
        spdlog::error( "[DB] Error while query teamserver list: {}", query.lastError().text().toStdString() );
        return TeamserverList;
    }

    /* iterating over the queried list */
    while ( query.next() ) {
        TeamserverList.push_back( {
            .Name     = query.value( "ProfileName" ).toString(),
            .Host     = query.value( "Host" ).toString(),
            .Port     = query.value( "Port" ).toString(),
            .User     = query.value( "User" ).toString(),
            .Password = query.value( "Password" ).toString(),
        } );
    }

    return TeamserverList;
}

bool HavocSpace::DBManager::removeAllTeamservers() {
    auto query = QSqlQuery();

    query.prepare( "delete from Teamservers" );

    if ( ! query.exec() ) {
        spdlog::error( "[DB] Error while deleting teamservers: {}", query.lastError().text().toStdString() );

        return false;
    }

    return true;
}
