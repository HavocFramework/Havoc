#include <global.hpp>
#include <Havoc/Havoc.hpp>
#include <Havoc/CmdLine.hpp>

int main( int argc, char** argv )
{
    auto Arguments = cmdline::parser();
    auto HavocApp  = QApplication( argc, argv );
    QTextCodec* codec = QTextCodec::codecForName( "UTF-8" );
    QTextCodec::setCodecForLocale( codec );

    spdlog::set_pattern( "[%T] [%^%l%$] %v" );
    spdlog::info( "Havoc Framework [Version: {}] [CodeName: {}]", HavocNamespace::Version, HavocNamespace::CodeName );

    Arguments.add( "debug", '\0', "debug mode" );
    Arguments.parse_check( argc, argv );

    if ( Arguments.exist( "debug" ) )
    {
        spdlog::set_level( spdlog::level::debug );
        spdlog::debug( "Debug mode enabled" );
        HavocX::DebugMode = true;
    }

    QGuiApplication::setWindowIcon( QIcon( ":/Havoc.ico" ) );

    HavocNamespace::HavocApplication = new HavocNamespace::HavocSpace::Havoc( new QMainWindow );
    HavocNamespace::HavocApplication->Init( argc, argv );

    int AppStatus = QApplication::exec();

    spdlog::info( "Havoc Application status: {}", AppStatus );

    return AppStatus;
}
