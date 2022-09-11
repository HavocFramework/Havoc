#include <global.hpp>

#include <Havoc/Havoc.hpp>

#include <QMultiMap>

int main( int argc, char** argv )
{
    QApplication HavocApp( argc, argv );

    spdlog::set_pattern( "[%T] [%^%l%$] %v" );
    spdlog::set_level( spdlog::level::debug );

    spdlog::info( "Havoc Framework [Version: {}] [CodeName: {}]", HavocNamespace::Version, HavocNamespace::CodeName );

    // Set font
    {
        u32     id     = QFontDatabase::addApplicationFont( ":/icons/Monaco" );
        QString family = QFontDatabase::applicationFontFamilies( id ).at( 0 );

        QFont monospace( family );
        monospace.setPointSize( 9 );
        QApplication::setFont( monospace );
    }

    QGuiApplication::setWindowIcon( QIcon( ":/Havoc.ico" ) );

    HavocNamespace::HavocApplication = new HavocNamespace::HavocSpace::Havoc( new QMainWindow );
    HavocNamespace::HavocApplication->Init( argc, argv );

    int AppStatus = QApplication::exec();

    spdlog::info( "Havoc Application status: {}", AppStatus );

    return AppStatus;
}
