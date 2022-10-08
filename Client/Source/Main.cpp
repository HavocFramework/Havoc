#include <global.hpp>
#include <Havoc/Havoc.hpp>
#include <Havoc/CmdLine.hpp>

int main( int argc, char** argv )
{
    auto Arguments = cmdline::parser();
    auto HavocApp  = QApplication( argc, argv );

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

    auto FontID = QFontDatabase::addApplicationFont( ":/icons/Monaco" );
    auto Family = QFontDatabase::applicationFontFamilies( FontID ).at( 0 );
    auto Monaco = QFont( Family );

    Monaco.setPointSize( 9 );
    QApplication::setFont( Monaco );

    QGuiApplication::setWindowIcon( QIcon( ":/Havoc.ico" ) );

    HavocNamespace::HavocApplication = new HavocNamespace::HavocSpace::Havoc( new QMainWindow );
    HavocNamespace::HavocApplication->Init( argc, argv );

    int AppStatus = QApplication::exec();

    spdlog::info( "Havoc Application status: {}", AppStatus );

    return AppStatus;
}
