#include <Havoc.h>
#include <core/HcPluginManager.h>
#include <Python.h>

class HcCoreApp : public IHcApplication {

public:
    ~HcCoreApp() override = default;

    auto StyleSheet(
        void
    ) -> QString override {
        return Havoc->StyleSheet();
    }

    auto MainWindowWidget(
        void
    ) -> QMainWindow* override {
        return Havoc->ui;
    }

    auto PageAgentAddTab(
        const std::string& name,
        const QIcon&       icon,
        QWidget*           widget
    ) -> void override {
        Havoc->ui->PageAgent->addTab(
            QString::fromStdString( name ),
            icon,
            widget
        );
    }

    auto RegisterAgentAction(
        const std::string&           action_name,
        const QIcon&                 action_icon,
        HcFnCallbackCtx<std::string> action_func,
        const std::string&           agent_type
    ) -> void override {
        auto action = new HcApplication::ActionObject;

        action->type       = HcApplication::ActionObject::ActionAgent;
        action->name       = action_name;
        action->icon       = action_icon;
        action->callback   = reinterpret_cast<HcFnCallbackCtx<void*>>( action_func );
        action->agent.type = agent_type;

        spdlog::debug( "action( {} )->icon: {}", action->name, action->icon.isNull() );

        Havoc->AddAction( action );
    }

    auto RegisterAgentAction(
        const std::string&           action_name,
        const QIcon&                 action_icon,
        HcFnCallbackCtx<std::string> action_func
    ) -> void override {
        auto action = new HcApplication::ActionObject;

        action->type     = HcApplication::ActionObject::ActionAgent;
        action->name     = action_name;
        action->icon     = action_icon;
        action->callback = reinterpret_cast<HcFnCallbackCtx<void*>>( action_func );

        Havoc->AddAction( action );
    }

    auto RegisterAgentAction(
        const std::string&           action_name,
        HcFnCallbackCtx<std::string> action_func,
        bool                         multi_select
    ) -> void override {
        //
        // TODO: implement
        //
    }

    auto RegisterMenuAction(
        const std::string& action_name,
        const QIcon&       action_icon,
        HcFnCallback       action_func
    ) -> void override {
        auto action = new HcApplication::ActionObject;

        action->type     = HcApplication::ActionObject::ActionHavoc;
        action->name     = action_name;
        action->icon     = action_icon;
        action->callback = reinterpret_cast<HcFnCallbackCtx<void*>>( action_func );

        Havoc->AddAction( action );
    };

    auto Agent(
        const std::string& uuid
    ) -> std::optional<IHcAgent *> override {
        return Havoc->Agent( uuid );
    }

    auto PythonContextRun(
        std::function<void()> function,
        bool                  concurrent
    ) -> std::optional<std::runtime_error> override {
        auto gil = py11::gil_scoped_acquire();

        if ( concurrent ) {
            //
            // start the python context run in a separate thread
            auto future = QtConcurrent::run( []( std::function<void()> Fn ) {
                HcPythonAcquire();
                Fn();
            }, function );
        } else {
            HcPythonAcquire();
            function();
        }

        return std::nullopt;
    }
};

HcPluginManager::HcPluginManager() : core_app( new HcCoreApp ) {}

auto HcPluginManager::loadPlugin(
    const std::string& path
) -> void {
    auto loader = QPluginLoader( QString::fromStdString( path ) );
    auto plugin = qobject_cast<IHcPlugin*>( loader.instance() );

    spdlog::debug( "loader.instance(): {} ({}) factory: {}",
        fmt::ptr( loader.instance() ),
        loader.instance()->metaObject()->className(),
        fmt::ptr( plugin )
    );

    if ( !plugin ) {
        spdlog::error(
            "HcPluginManager::loadPlugin failed to load plugin {}: {}",
            path, loader.errorString().toStdString()
        );
        return;
    }

    spdlog::debug(
        "HcPluginManager::loadPlugin loaded {} @ {}",
        loader.metaData().value( "IID" ).toString().toStdString(),
        fmt::ptr( plugin )
    );

    plugin->main( core_app );

    plugins.push_back( plugin );
}