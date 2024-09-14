#include <Havoc.h>
#include <core/HcAgent.h>

HcAgent::HcAgent(
    const json& metadata
) : data( metadata ) {}

auto HcAgent::initialize() -> bool {
    auto arch    = QString();
    auto user    = QString();
    auto host    = QString();
    auto local   = QString();
    auto path    = QString();
    auto process = QString();
    auto pid     = QString();
    auto tid     = QString();
    auto system  = QString();
    auto note    = QString();
    auto meta    = json();

    if ( data.contains( "uuid" ) && data[ "uuid" ].is_string() ) {
        uuid = data[ "uuid" ].get<std::string>();
    } else {
        spdlog::error( "[HcAgent::parse] agent does not contain valid uuid" );
        return false;
    }

    if ( data.contains( "type" ) && data[ "type" ].is_string() ) {
        type = data[ "type" ].get<std::string>();
    } else {
        spdlog::error( "[HcAgent::parse] agent does not contain valid type" );
        return false;
    }

    if ( data.contains( "parent" ) && data[ "parent" ].is_string() ) {
        parent = data[ "type" ].get<std::string>();
    }

    if ( data.contains( "note" ) && data[ "note" ].is_string() ) {
        note = QString( data[ "note" ].get<std::string>().c_str() );
    } else {
        spdlog::debug( "[HcAgent::parse] agent does not contain any note" );
    }

    if ( data.contains( "meta" ) && data[ "meta" ].is_object() ) {
        meta = data[ "meta" ].get<json>();
    } else {
        spdlog::debug( "[HcAgent::parse] agent does not contain valid meta object" );
        return false;
    }

    if ( meta.contains( "user" ) && meta[ "user" ].is_string() ) {
        user = QString( meta[ "user" ].get<std::string>().c_str() );
    } else {
        spdlog::debug( "[HcAgent::parse] agent does not contain valid meta user" );
    }

    if ( meta.contains( "host" ) && meta[ "host" ].is_string() ) {
        host = QString( meta[ "host" ].get<std::string>().c_str() );
    } else {
        spdlog::debug( "[HcAgent::parse] agent does not contain valid meta host" );
    }

    if ( meta.contains( "arch" ) && meta[ "arch" ].is_string() ) {
        arch = QString( meta[ "arch" ].get<std::string>().c_str() );
    } else {
        spdlog::debug( "[HcAgent::parse] agent does not contain valid meta arch" );
    }

    if ( meta.contains( "local ip" ) && meta[ "local ip" ].is_string() ) {
        local = QString( meta[ "local ip" ].get<std::string>().c_str() );
    } else {
        spdlog::debug( "[HcAgent::parse] agent does not contain valid meta local ip" );
    }

    if ( meta.contains( "process path" ) && meta[ "process path" ].is_string() ) {
        path = QString( meta[ "process path" ].get<std::string>().c_str() );
    } else {
        spdlog::debug( "[HcAgent::parse] agent does not contain valid meta process path" );
    }

    if ( meta.contains( "process name" ) && meta[ "process name" ].is_string() ) {
        process = QString( meta[ "process name" ].get<std::string>().c_str() );
    } else {
        spdlog::debug( "[HcAgent::parse] agent does not contain valid meta process name" );
    }

    if ( meta.contains( "pid" ) && meta[ "pid" ].is_number_integer() ) {
        pid = QString::number( meta[ "pid" ].get<int>() );
    } else {
        spdlog::debug( "[HcAgent::parse] agent does not contain valid meta pid" );
    }

    if ( meta.contains( "tid" ) && meta[ "tid" ].is_number_integer() ) {
        tid = QString::number( meta[ "tid" ].get<int>() );
    } else {
        spdlog::debug( "[HcAgent::parse] agent does not contain valid meta tid" );
    }

    if ( meta.contains( "system" ) && meta[ "system" ].is_string() ) {
        system = QString( meta[ "system" ].get<std::string>().c_str() );
    } else {
        spdlog::debug( "[HcAgent::parse] agent does not contain valid meta system" );
    }

    if ( meta.contains( "last callback" ) && meta[ "last callback" ].is_string() ) {
        last = QString( meta[ "last callback" ].get<std::string>().c_str() );
    } else {
        spdlog::debug( "[HcAgent::parse] agent does not contain valid meta last" );
    }

    ui.table = {
        .Uuid        = new HcAgentTableItem( uuid.c_str(), this ),
        .Internal    = new HcAgentTableItem( local, this ),
        .Username    = new HcAgentTableItem( user, this ),
        .Hostname    = new HcAgentTableItem( host, this ),
        .ProcessPath = new HcAgentTableItem( path, this ),
        .ProcessName = new HcAgentTableItem( process, this ),
        .ProcessId   = new HcAgentTableItem( pid, this ),
        .ThreadId    = new HcAgentTableItem( tid, this ),
        .Arch        = new HcAgentTableItem( arch, this ),
        .System      = new HcAgentTableItem( system, this ),
        .Note        = new HcAgentTableItem( note, this, Qt::NoItemFlags, Qt::AlignVCenter ),
        .Last        = new HcAgentTableItem( last, this ),
    };

    console = new HcAgentConsole( this );
    console->setBottomLabel( QString( "[User: %1] [Process: %2] [Pid: %3] [Tid: %4]" ).arg( user ).arg( path ).arg( pid ).arg( tid ) );
    console->setInputLabel( ">>>" );
    console->LabelHeader->setFixedHeight( 0 );

    //
    // if an interface has been registered then assign it to the agent
    //
    interface = std::nullopt;
    if ( auto interface = Havoc->AgentObject( type ); interface.has_value() ) {
        HcPythonAcquire();

        try {
            interface = interface.value()( uuid, type, meta );
        } catch ( py11::error_already_set &eas ) {
            spdlog::error( "failed to invoke agent interface [uuid: {}] [type: {}]: \n{}", uuid, type, eas.what() );
        }
    }

    return true;
}

auto HcAgent::remove() -> void {
    auto result = httplib::Result();

    result = Havoc->ApiSend( "/api/agent/remove", { { "uuid", uuid } } );

    if ( result->status != 200 ) {
        Helper::MessageBox(
            QMessageBox::Critical,
            "agent removal failure",
            std::format( "failed to remove agent {}: {}", uuid, result->body )
        );

        spdlog::error( "failed to remove agent {}: {}", uuid, result->body );

        return;
    }
}

auto HcAgent::hide() -> void {
    auto result = httplib::Result();

    result = Havoc->ApiSend( "/api/agent/hide", {
        { "uuid", uuid },
        { "hide", true }
    } );

    if ( result->status != 200 ) {
        Helper::MessageBox(
            QMessageBox::Critical,
            "agent hide failure",
            std::format( "failed to hide agent {}: {}", uuid, result->body )
        );

        spdlog::error( "failed to hide agent {}: {}", uuid, result->body );

        return;
    }
}