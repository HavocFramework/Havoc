#ifndef HAVOC_PACKAGER_H
#define HAVOC_PACKAGER_H

#include <global.hpp>

using namespace std;
using namespace HavocNamespace;
using namespace HavocSpace;

namespace HavocNamespace::Util::Packager
{
    typedef struct
    {
        int Event;

        string User;
        string Time;
        string OneTime;
    } Head_t;

    typedef struct
    {
        int SubEvent;
        QMap<string, string> Info; // TODO: make it QJsonObject
    } Body_t ;

    typedef struct Package
    {
        Head_t Head;
        Body_t Body;
    } Package, *PPackage;

    // TODO: make everyone a struct with static members
    namespace InitConnection
    {
        extern const int Type;
        extern const int Success;
        extern const int Error;
        extern const int Login;
    }

    namespace Listener
    {
        extern const int Type;

        extern const int Add;
        extern const int Remove;
        extern const int Edit;
        extern const int Mark;
        extern const int Error;
    }

    namespace Chat
    {
        extern const int Type;

        extern const int NewMessage;
        extern const int NewListener;
        extern const int NewUser;
        extern const int UserDisconnect;
        extern const int NewSession;
    }

    namespace Gate
    {
        extern const int Type;

        extern const int Staged;
        extern const int Stageless;
        extern const int MSOffice;
    }

    namespace Session
    {
        extern const int Type;

        extern const int NewSession;
        extern const int SendCommand;
        extern const int ReceiveCommand;
        extern const int MarkAs;
        extern const int Remove;
    }

    namespace Service
    {
        extern const int Type;
        extern const int AgentRegister;
        extern const int ListenerRegister;
    }

    namespace Teamserver
    {
        extern const int Type;
        extern const int Logger;
        extern const int Profile;
    }
}

auto NewPackageCommand( const QString& Teamserver, Util::Packager::Body_t Body ) -> void;

class HavocSpace::Packager
{
private:
    QString TeamserverName;
public:
    static Util::Packager::PPackage DecodePackage(const QString& Package );
    QJsonDocument EncodePackage( Util::Packager::Package Package );

    bool DispatchPackage( Util::Packager::PPackage Package );
    void setTeamserver(QString Name);

public:
    bool DispatchInitConnection( Util::Packager::PPackage Package );
    bool DispatchListener( Util::Packager::PPackage Package );
    bool DispatchChat( Util::Packager::PPackage Package );
    bool DispatchSession( Util::Packager::PPackage Package );
    bool DispatchGate( Util::Packager::PPackage Package );
    bool DispatchService( Util::Packager::PPackage Package );
    bool DispatchTeamserver( Util::Packager::PPackage Package );
};

#endif //HAVOC_PACKAGER_H
