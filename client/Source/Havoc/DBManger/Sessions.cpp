#include <global.hpp>
#include <Havoc/DBManager/DBManager.hpp>

using namespace HavocNamespace;
using namespace HavocNamespace::HavocSpace;

bool DBManager::addSession(const QString& TeamserverID, HavocNamespace::Util::SessionItem session)
{
    QSqlQuery query;

    query.prepare(
            "insert into Session "
            "(TeamserverID, NameID, External, Internal, Listener, User, Computer, OS, Process, PID, Arch, Last)"
            " values(:TeamserverID, :NameID, :External, :Internal, :Listener, :User, :Computer, :OS, :Process, :PID, :Arch, :Last )"
            );

    query.bindValue(":TeamserverID", TeamserverID);
    query.bindValue(":NameID", session.Name);
    query.bindValue(":External", session.External);
    query.bindValue(":Internal", session.Internal);
    query.bindValue(":Listener", session.Listener);
    query.bindValue(":User", session.User);
    query.bindValue(":Computer", session.Computer);
    query.bindValue(":OS", session.OS);
    query.bindValue(":Process", session.Process);
    query.bindValue(":PID", session.PID);
    query.bindValue(":Arch", session.Arch);
    query.bindValue(":Last", session.Last);

    if (!query.exec()) {
        cout << "[!] Failed to add Session \"" << session.Name.toStdString() << "\" to Database :: " << query.lastError().text().toStdString() << endl;
        return false;
    }

    return false;
}

bool DBManager::removeSession( const QString& TeamserverID, const QString& DemonSessionID )
{
    QSqlQuery query;

    query.prepare("delete from Session where NameID = :DemonSessionID and TeamserverID = :TeamserverID");

    query.bindValue(":DemonSessionID", DemonSessionID);
    query.bindValue(":TeamserverID", TeamserverID);

    if (!query.exec())
    {
        spdlog::warn("Couldn't remove Demon Session \"{}\": {}", DemonSessionID.toStdString(), query.lastError().text().toStdString());
        return false;
    }
    return true;
}

vector<Util::SessionItem> DBManager::listSessions() {
    vector<Util::SessionItem> List;

    QSqlQuery query;

    query.prepare("select * from Session");
    if (!query.exec()) {
        spdlog::warn("Error while query for Session: {}", query.lastError().text().toStdString());
        return List;
    }

    while (query.next()) {
        List.push_back((Util::SessionItem){
                .TeamserverID   = query.value("TeamserverID").toString(),
                .Name           = query.value("NameID").toString(),
                .External       = query.value("External").toString(),
                .Internal       = query.value("Internal").toString(),
                .Listener       = query.value("Listener").toString(),
                .User           = query.value("User").toString(),
                .Computer       = query.value("Computer").toString(),
                .OS             = query.value("OS").toString(),
                .Process        = query.value("Process").toString(),
                .PID            = query.value("PID").toString(),
                .Arch           = query.value("Arch").toString(),
                .Last           = query.value("Last").toString(),
        });
    }
    return List;
}
