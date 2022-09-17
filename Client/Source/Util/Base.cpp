#include <Util/Base.hpp>

auto FileRead( const QString& FilePath ) -> QByteArray
{
    auto Content = QByteArray( );

    if ( FilePath[ 0 ] != ':' )
    {
        if ( ! QFile::exists( FilePath ) )
        {
            spdlog::error( "Failed to find file: {}", FilePath.toStdString() );
            return nullptr;
        }
    }

    // Open File
    auto File = QFile( FilePath );
    File.open( QIODevice::ReadOnly );

    // Read everything into our byte array buffer
    Content = File.readAll();

    // close file
    File.close();

    return Content;
}

auto MessageBox( QString Title, QString Text, QMessageBox::Icon Icon ) -> void
{
    auto box = QMessageBox();

    box.setWindowTitle( Title );
    box.setText( Text );
    box.setIcon( Icon );
    box.setStyleSheet( FileRead( ":/stylesheets/MessageBox" ) );
    box.exec();
}