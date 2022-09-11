#include <Havoc/DBManager/DBManager.hpp>
#include <QSqlError>

using namespace HavocNamespace;

bool HavocSpace::DBManager::addTeamserverInfo(Util::ConnectionInfo connection) {
    QSqlQuery query;
    bool success = true;
    query.prepare(
            "insert into Teamservers (ProfileName, Host, Port, User, Password) values(:ProfileName, :Host, :Port, :User, :Password)"
            );

    // query.bindValue(":ID", std::to_string(HavocSpace::TeamserverConnections.size()).c_str());
    query.bindValue(":ProfileName", connection.Name.toStdString().c_str());
    query.bindValue(":Host", connection.Host.toStdString().c_str());
    query.bindValue(":Port", connection.Port.toStdString().c_str());
    query.bindValue(":User", connection.User.toStdString().c_str());
    query.bindValue(":Password", connection.Password.toStdString().c_str());

    success = query.exec();

    if (!success)
        cout << "[!] Error :: " << query.lastError().text().toStdString() << endl;

    return success;
}

bool HavocSpace::DBManager::checkTeamserverExists(const QString &ProfileName) {
    QSqlQuery query;

    query.prepare("select * from Teamservers");
    if (!query.exec()) {
        cout << "[!] Error while query for Teamservers :: " << query.lastError().text().toStdString() << endl;
        return false;
    }

    while (query.next())
    {
        if (query.value("ProfileName") == ProfileName)
            return true;
    }

    return false;
}

bool HavocSpace::DBManager::removeTeamserverInfo(const QString &ProfileName) {
    QSqlQuery query;

    query.prepare("delete from Teamservers where ProfileName = :ProfileName");
    query.bindValue(":ProfileName", ProfileName);

    if (!query.exec()) {
        cout << "[!] Error while deleting \"" << ProfileName.toStdString() << "\"" << "from Teamservers :: " << query.lastError().text().toStdString() << endl;
        return false;
    }

    return true;
}

vector<Util::ConnectionInfo> HavocSpace::DBManager::listTeamservers()
{
    auto TeamserverList = vector<Util::ConnectionInfo>();
    auto query          = QSqlQuery();

    query.prepare( "select * from Teamservers" );
    if ( ! query.exec() )
    {
        spdlog::error( "Error while query for Teamservers: {}", query.lastError().text().toStdString() );
        return TeamserverList;
    }

    while ( query.next() )
    {
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
    QSqlQuery query;

    query.prepare("delete from Teamservers");

    if (!query.exec()) {
        cout << "[!] Error while deleting all data from Teamservers :: " << query.lastError().text().toStdString() << endl;
        return false;
    }

    return true;
}
