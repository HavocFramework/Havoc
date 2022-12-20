#include <Havoc/DBManager/DBManager.hpp>

bool HavocNamespace::HavocSpace::DBManager::AddScript( QString Path )
{
    auto query = QSqlQuery();

    query.prepare( "insert into Scripts (Path) values(:Path)" );
    query.bindValue( ":Path", Path );

    if ( ! query.exec() )
    {
        spdlog::error( "[DB] Failed to add Script: {}", query.lastError().text().toStdString() );
        return false;
    }

    return true;
}

bool HavocNamespace::HavocSpace::DBManager::RemoveScript( QString Path )
{
    auto query = QSqlQuery();

    query.prepare( "delete from Scripts where Path = :Path" );
    query.bindValue(":Path", Path);

    if ( ! query.exec() )
    {
        spdlog::error( "[DB] Couldn't delete {} from Scripts: {}", Path.toStdString(), query.lastError().text().toStdString() );
        return false;
    }

    return true;
}

bool HavocNamespace::HavocSpace::DBManager::CheckScript( QString Path )
{
    auto query = QSqlQuery();

    query.prepare( "select * from Scripts" );
    if ( ! query.exec() )
    {
        spdlog::error( "[DB] Couldn't query Scripts: {}", query.lastError().text().toStdString() );
        return false;
    }

    while ( query.next() )
    {
        if ( query.value( "Path" ) == Path )
            return true;
    }

    return false;
}

vector<QString> HavocNamespace::HavocSpace::DBManager::GetScripts()
{
    auto List   = vector<QString>();
    auto query  = QSqlQuery();

    query.prepare( "select * from Scripts" );
    if ( ! query.exec() )
    {
        spdlog::error( "[DB] Couldn't query Scripts: {}", query.lastError().text().toStdString() );
        return List;
    }

    while ( query.next() )
        List.push_back( query.value("Path").toString() );

    return List;
}