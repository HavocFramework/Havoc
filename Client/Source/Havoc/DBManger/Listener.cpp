#include <Havoc/DBManager/DBManager.hpp>

using namespace HavocNamespace;

bool HavocSpace::DBManager::addListener( Util::ListenerItem Listener )
{
    QSqlQuery query;

    query.prepare(
            "insert into Listeners "
            "(TeamserverID, Name, Protocol, Host, Port, Connected, Status) "
            "values(:TeamserverID, :Name, :Protocol, :Host, :Port, :Connected, :Status)"
            );

    query.bindValue(":TeamserverID",
                    Listener.TeamserverID.c_str() );
    query.bindValue(":Name",
                    Listener.Name.c_str() );
    query.bindValue(":Protocol",
                    Listener.Protocol.c_str() );
    query.bindValue(":Host",
                    Listener.Host.c_str() );
    query.bindValue(":Port",
                    Listener.Port.c_str() );
    query.bindValue(":Connected",
                    Listener.Connected.c_str() );
    query.bindValue(":Status",
                    Listener.Status.c_str() );

    if ( ! query.exec() )
    {
        cout << "[!] Failed to add new Listener :: " << query.lastError().text().toStdString() << endl;
        return false;
    }
    return true;
}