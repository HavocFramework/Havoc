#include <global.hpp>
#include <Havoc/Havoc.hpp>
#include <QTimer>

auto main(
    int    argc,
    char** argv
) -> int {
    auto HavocApp = QApplication( argc, argv );
    auto Status   = 0;

    QGuiApplication::setWindowIcon( QIcon( ":/Havoc.ico" ) );

    HavocNamespace::HavocApplication = new HavocNamespace::HavocSpace::Havoc( new QMainWindow );
    HavocNamespace::HavocApplication->Init( argc, argv );

    Status = QApplication::exec();

    spdlog::info( "Havoc Application status: {}", Status );

    return Status;
}
