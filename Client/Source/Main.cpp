#include <global.hpp>

#include <Havoc/Havoc.hpp>

#include <QMultiMap>

int main( int argc, char** argv )
{
    QApplication HavocApp( argc, argv );

    spdlog::set_pattern( "[%T] [%^%l%$] %v" );
    spdlog::set_level( spdlog::level::debug );

    spdlog::info( "Havoc Framework [Version: {}] [CodeName: {}]", HavocNamespace::Version, HavocNamespace::CodeName );

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
