#include <Havoc.h>

auto HavocClient::eventDispatch(
    const json& event
) -> void {
    auto type = std::string();
    auto data = json();

    if ( ! event.contains( "type" ) ) {
        spdlog::debug( "invalid event: {}", event.dump() );
        return;
    }

    if ( ! event.contains( "data" ) ) {
        spdlog::debug( "invalid event: {}", event.dump() );
        return;
    }

    type = event[ "type" ].get<std::string>();
    data = event[ "data" ].get<json>();

    if ( type == Event::user::login )
    {
        if ( data.empty() ) {
            spdlog::error( "user::login: invalid package (data emtpy)" );
            return;
        }
    }
    else if ( type == Event::user::logout )
    {
        if ( data.empty() ) {
            spdlog::error( "user::logout: invalid package (data emtpy)" );
            return;
        }
    }
    else if ( type == Event::user::message )
    {

    }
    else if ( type == Event::listener::add )
    {
        if ( data.empty() ) {
            spdlog::error( "listener::register: invalid package (data emtpy)" );
            return;
        }

        Gui->PageListener->Protocols.push_back( data );
        Gui->PagePayload->RefreshBuilders();
    }
    else if ( type == Event::listener::start )
    {
        if ( data.empty() ) {
            spdlog::error( "Event::listener::start: invalid package (data emtpy)" );
            return;
        }

        AddListener( data );
    }
    else if ( type == Event::listener::edit )
    {

    }
    else if ( type == Event::listener::stop )
    {

    }
    else if ( type == Event::listener::status )
    {
        auto name = std::string();
        auto log  = std::string();

        if ( data.empty() ) {
            spdlog::error( "Event::listener::status: invalid package (data emtpy)" );
            return;
        }

        if ( data.contains( "name" ) ) {
            if ( data[ "name" ].is_string() ) {
                name = data[ "name" ].get<std::string>();
            } else {
                spdlog::error( "invalid listener status: \"name\" is not string" );
                return;
            }
        } else {
            spdlog::error( "invalid listener status: \"name\" is not found" );
            return;
        }

        if ( data.contains( "status" ) ) {
            if ( data[ "status" ].is_string() ) {
                log = data[ "status" ].get<std::string>();
            } else {
                spdlog::error( "invalid listener status: \"status\" is not string" );
                return;
            }
        } else {
            spdlog::error( "invalid listener status: \"status\" is not found" );
            return;
        }

        Gui->PageListener->setListenerStatus( name, log );
        Gui->PagePayload->RefreshBuilders();
    }
    else if ( type == Event::listener::log )
    {
        auto name = std::string();
        auto log  = std::string();

        if ( data.empty() ) {
            spdlog::error( "Event::listener::log: invalid package (data emtpy)" );
            return;
        }

        if ( data.contains( "name" ) ) {
            if ( data[ "name" ].is_string() ) {
                name = data[ "name" ].get<std::string>();
            } else {
                spdlog::error( "invalid listener log: \"name\" is not string" );
                return;
            }
        } else {
            spdlog::error( "invalid listener log: \"name\" is not found" );
            return;
        }

        if ( data.contains( "log" ) ) {
            if ( data[ "log" ].is_string() ) {
                log = data[ "log" ].get<std::string>();
            } else {
                spdlog::error( "invalid listener log: \"log\" is not string" );
                return;
            }
        } else {
            spdlog::error( "invalid listener log: \"log\" is not found" );
            return;
        }

        Gui->PageListener->addListenerLog( name, log );
    }
    else if ( type == Event::agent::add )
    {
        Gui->PagePayload->RefreshBuilders();
    }
    else if ( type == Event::agent::initialize )
    {
        if ( data.empty() ) {
            spdlog::error( "Event::agent::initialize: invalid package (data emtpy)" );
            return;
        }

        spdlog::debug( "Agent: {}", data.dump() );

        Gui->PagePayload->RefreshBuilders();
        Gui->PageAgent->addAgent( data );
    }
    else if ( type == Event::agent::callback )
    {
        auto uuid          = std::string();
        auto typ           = std::string();
        auto arg           = json();
        auto uid           = int();
        auto pat           = std::string();
        auto out           = std::string();
        auto callback_uuid = std::string();

        if ( data.empty() ) {
            spdlog::error( "Event::agent::callback: invalid package (data emtpy)" );
            return;
        }

        if ( data.contains( "uuid" ) ) {
            if ( data[ "uuid" ].is_string() ) {
                uuid = data[ "uuid" ].get<std::string>();
            } else {
                spdlog::error( "invalid agent callback: \"uuid\" is not string" );
                return;
            }
        } else {
            spdlog::error( "invalid agent callback: \"uuid\" is not found" );
            return;
        }

        if ( data.contains( "type" ) ) {
            if ( data[ "type" ].is_string() ) {
                typ = data[ "type" ].get<std::string>();
            } else {
                spdlog::error( "invalid agent callback: \"type\" is not string" );
                return;
            }
        } else {
            spdlog::error( "invalid agent callback: \"type\" is not found" );
            return;
        }

        if ( typ == "console" ) {
            if ( data.contains( "data" ) ) {
                if ( data[ "data" ].is_object() ) {
                    arg = data[ "data" ].get<json>();
                } else {
                    spdlog::error( "invalid agent callback: \"data\" is not an object" );
                    return;
                }
            } else {
                spdlog::error( "invalid agent callback: \"data\" is not found" );
                return;
            }

            if ( arg.contains( "format" ) ) {
                if ( arg[ "format" ].is_string() ) {
                    pat = arg[ "format" ].get<std::string>();
                } else {
                    spdlog::error( "invalid agent callback: \"format\" is not string" );
                    return;
                }
            } else {
                spdlog::error( "invalid agent callback: \"format\" is not found" );
                return;
            }

            if ( arg.contains( "output" ) ) {
                if ( arg[ "output" ].is_string() ) {
                    out = arg[ "output" ].get<std::string>();
                } else {
                    spdlog::error( "invalid agent callback: \"output\" is not string" );
                    return;
                }
            } else {
                spdlog::error( "invalid agent callback: \"output\" is not found" );
                return;
            }

            Gui->PageAgent->AgentConsole( uuid, pat, out );
        } else if ( typ == "function" ) {
            spdlog::debug( "Event::agent::callback: function type callback -> {}", data.dump() );
            //
            // this type indicates that a callback function should be invoked
            // with the following callback uuid (inside the uuid member)
            //
            if ( data.contains( "data" ) ) {
                if ( data[ "data" ].is_object() ) {
                    arg = data[ "data" ].get<json>();

                    //
                    // get the data to pass to the callback
                    //
                    if ( arg.contains( "data" ) ) {
                        if ( arg[ "data" ].is_string() ) {
                            out = arg[ "data" ].get<std::string>();
                        } else {
                            spdlog::error( "invalid agent callback: \"output\" is not string" );
                            return;
                        }
                    } else {
                        spdlog::error( "invalid agent callback: \"output\" is not found" );
                        return;
                    }

                    //
                    // get the task uuid to pass to the callback
                    //
                    if ( arg.contains( "callback" ) ) {
                        if ( arg[ "callback" ].is_string() ) {
                            callback_uuid = arg[ "callback" ].get<std::string>();
                        } else {
                            spdlog::error( "invalid agent callback: \"callback\" is not a string" );
                            return;
                        }
                    } else {
                        spdlog::error( "invalid agent callback: \"callback\" is not found" );
                        return;
                    }

                    //
                    // get the task uuid to pass to the callback
                    //
                    if ( arg.contains( "task-uuid" ) ) {
                        if ( arg[ "task-uuid" ].is_number() ) {
                            uid = arg[ "task-uuid" ].get<int>();
                        } else {
                            spdlog::error( "invalid agent callback: \"task-uuid\" is not a number" );
                            return;
                        }
                    } else {
                        spdlog::error( "invalid agent callback: \"task-uuid\" is not found" );
                        return;
                    }

                    //
                    // get registered callback object
                    //
                    if ( auto callback = Havoc->CallbackObject( callback_uuid ) ) {
                        //
                        // did we found a callback based on the uuid ?
                        //
                        if ( callback.has_value() ) {
                            //
                            // acquire python gil to interact with the
                            // python function and call the callback
                            //
                            py11::gil_scoped_acquire gil;

                            //
                            // search for the agent via the specified uuid
                            //
                            if ( auto agent = Havoc->Gui->PageAgent->Agent( uuid ) ) {
                                //
                                // check if we found the agent and if
                                // it contains a python interface
                                //
                                if ( agent.has_value() && agent.value()->interface.has_value() ) {
                                    spdlog::debug( "agent found and invoking callback: {}", agent.value()->uuid );

                                    pat = QByteArray::fromBase64( out.c_str() ).toStdString();

                                    //
                                    // actually invoke the callback with following arguments:
                                    //
                                    //   def callback( agent: HcAgent, task_uuid: int, data: bytes ):
                                    //      # agent interface can be invoked now
                                    //      return
                                    //
                                    // TODO: maybe use kwargs instead ?
                                    //       kwargs can contain multiple things like context, task-uuid, etc.
                                    //       which i think is better and more modular since it
                                    //
                                    //   def callback( agent: HcAgent, data: bytes, **kwargs ):
                                    //      # agent interface can be invoked now
                                    //      return
                                    //
                                    callback.value()(
                                        agent.value()->interface.value(),
                                        py11::int_( uid ),
                                        py11::bytes( pat.c_str(), pat.length() )
                                    );
                                } else {
                                    spdlog::error(
                                        "[agent.has_value(): {}] [agent.value()->interface.has_value(): {}]",
                                        agent.has_value(),
                                        agent.has_value() ? agent.value()->interface.has_value() : false
                                    );
                                }
                            }
                        } else {
                            spdlog::error( "CallbackObject has no value: {}", callback_uuid );
                        }
                    } else {
                        spdlog::error( "CallbackObject not found: {}", callback_uuid );
                    }
                } else {
                    spdlog::error( "invalid agent callback: \"data\" is not an object" );
                    return;
                }
            } else {
                spdlog::error( "invalid agent callback: \"data\" is not found" );
                return;
            }


        }
    }
    else if ( type == Event::agent::console )
    {

    }
    else if ( type == Event::agent::input )
    {

    }
    else if ( type == Event::agent::task )
    {

    }
    else if ( type == Event::agent::status )
    {

    }
    else if ( type == Event::agent::remove )
    {

    }
    else if ( type == Event::agent::buildlog )
    {
        auto log = std::string();

        if ( data.empty() ) {
            spdlog::error( "Event::agent::buildlog: invalid package (data emtpy)" );
            return;
        }

        if ( data.contains( "log" ) ) {
            if ( data[ "log" ].is_string() ) {
                log = data[ "log" ].get<std::string>();
            } else {
                spdlog::error( "invalid agent build log: \"log\" is not string" );
                return;
            }
        } else {
            spdlog::error( "invalid agent build log: \"log\" is not found" );
            return;
        }

        Gui->PagePayload->TextBuildLog->append( log.c_str() );
    } else {
        spdlog::debug( "invalid event: {} not found", type );
    }
}


