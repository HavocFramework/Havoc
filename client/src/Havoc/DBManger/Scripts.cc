#include <Havoc/DBManager/DBManager.hpp>

bool HavocNamespace::HavocSpace::DBManager::AddScript( QString Path )
{
    auto query = QSqlQuery();
    auto error = std::string();

    query.prepare( "insert into Scripts (Path) values(:Path)" );
    query.bindValue( ":Path", Path );

    if ( ! query.exec() ) {
        error = query.lastError().text().toStdString();
        spdlog::error( "[DB] Failed to add Script: {}", error );
        return false;
    }

    return true;
}

bool HavocNamespace::HavocSpace::DBManager::RemoveScript( QString Path )
{
    auto query = QSqlQuery();
    auto error = std::string();
    auto path  = std::string();

    query.prepare( "delete from Scripts where Path = :Path" );
    query.bindValue( ":Path", Path );

    if ( ! query.exec() ) {
        error = query.lastError().text().toStdString();
        path  = Path.toStdString();

        spdlog::error( "[DB] Couldn't delete {} from Scripts: {}", path, error );

        return false;
    }

    return true;
}

bool HavocNamespace::HavocSpace::DBManager::CheckScript( QString Path )
{
    auto query = QSqlQuery();
    auto error = std::string();

    query.prepare( "select * from Scripts" );

    if ( ! query.exec() ) {
        error = query.lastError().text().toStdString();
        spdlog::error( "[DB] Couldn't query Scripts: {}", error );
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
    auto List  = vector<QString>();
    auto query = QSqlQuery();
    auto error = std::string();

    query.prepare( "select * from Scripts" );

    if ( ! query.exec() ) {
        error = query.lastError().text().toStdString();
        spdlog::error( "[DB] Couldn't query Scripts: {}", error );
        return List;
    }

    while ( query.next() )
        List.push_back( query.value("Path").toString() );

    return List;
}