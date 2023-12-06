#include <Util/Base.hpp>

auto FileRead( const QString& FilePath ) -> QByteArray
{
    auto Content = QByteArray( );
    auto path    = FilePath.toStdString();

    if ( FilePath[ 0 ] != ':' )
    {
        if ( ! QFile::exists( FilePath ) ) {
            spdlog::error( "Failed to find file: {}", path );
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

auto WinVersionIcon( QString OSVersion, bool High ) -> QIcon
{
    if ( OSVersion.startsWith( "Windows 10" ) || OSVersion.startsWith( "Windows Server 2019" )|| OSVersion.startsWith( "Windows 2019 Server" ) )
    {
        spdlog::debug( "OSVersion is Windows 10" );

        if ( High )
            return QIcon( ":/images/win10-8-high" );
        else
            return QIcon( ":/images/win10-8" );
    }
    else if ( OSVersion.startsWith( "Windows XP" )  )
    {
        spdlog::debug( "OSVersion is Windows XP" );

        if ( High )
            return QIcon( ":/images/winxp-high" );
        else
            return QIcon( ":/images/winxp" );
    }
    if ( OSVersion.startsWith( "Windows 8" ) || OSVersion.startsWith( "Windows Server 2012" ) )
    {
        spdlog::debug( "OSVersion is Windows 8" );

        if ( High )
            return QIcon( ":/images/win10-8-high" );
        else
            return QIcon( ":/images/win10-8" );
    }
    if ( OSVersion.startsWith( "Windows 11" )  )
    {
        spdlog::debug( "OSVersion is Windows 11" );

        if ( High )
            return QIcon( ":/images/win11-high" );
        else
            return QIcon( ":/images/win11" );
    }
    if ( OSVersion.startsWith( "Windows 7" ) || OSVersion.startsWith( "Windows Vista" ) )
    {
        spdlog::debug( "OSVersion is Windows 7 or Vista" );

        if ( High )
            return QIcon( ":/images/win7-vista-high" );
        else
            return QIcon( ":/images/win7-vista" );
    }
    if ( OSVersion.startsWith( "MacOS" )  )
    {
        spdlog::debug( "OSVersion is MacOS" );

        if ( High )
            return QIcon( ":/images/macos-high" );
        else
            return QIcon( ":/images/macos" );
    }
    if ( OSVersion.startsWith( "Linux" )  )
    {
        spdlog::debug( "OSVersion is Linux" );

        if ( High )
            return QIcon( ":/images/linux-high" );
        else
            return QIcon( ":/images/linux" );
    }
    else
    {
        if ( High )
            return QIcon( ":/images/unknown-high" );
        else
            return QIcon( ":/images/unknown" );
    }
}

auto WinVersionImage( QString OSVersion, bool High ) -> QImage
{
    if ( OSVersion.startsWith( "Windows 10" )  )
    {
        spdlog::debug( "OSVersion is Windows 10" );

        if ( High )
            return QImage( ":/images/win10-8-high" );
        else
            return QImage( ":/images/win10-8" );
    }
    else if ( OSVersion.startsWith( "Windows XP" )  )
    {
        spdlog::debug( "OSVersion is Windows XP" );

        if ( High )
            return QImage( ":/images/winxp-high" );
        else
            return QImage( ":/images/winxp" );
    }
    if ( OSVersion.startsWith( "Windows 8" )  )
    {
        spdlog::debug( "OSVersion is Windows 8" );

        if ( High )
            return QImage( ":/images/win10-8-high" );
        else
            return QImage( ":/images/win10-8" );
    }
    if ( OSVersion.startsWith( "Windows 11" )  )
    {
        spdlog::debug( "OSVersion is Windows 11" );

        if ( High )
            return QImage( ":/images/win11-high" );
        else
            return QImage( ":/images/win11" );
    }
    if ( OSVersion.startsWith( "Windows 7" ) || OSVersion.startsWith( "Windows Vista" ) )
    {
        spdlog::debug( "OSVersion is Windows 7 or Vista" );

        if ( High )
            return QImage( ":/images/win7-vista-high" );
        else
            return QImage( ":/images/win7-vista" );
    }
    if ( OSVersion.startsWith( "MacOS" )  )
    {
        spdlog::debug( "OSVersion is MacOS" );

        if ( High )
            return QImage( ":/images/macos-high" );
        else
            return QImage( ":/images/macos" );
    }
    if ( OSVersion.startsWith( "Linux" )  )
    {
        spdlog::debug( "OSVersion is Linux" );

        if ( High )
            return QImage( ":/images/linux-high" );
        else
            return QImage( ":/images/linux" );
    }
    else
    {
        if ( High )
            return QImage( ":/images/unknown-high" );
        else
            return QImage( ":/images/unknown" );
    }
}

auto CurrentDateTime(
    void
) -> QString {
    return ( QDateTime::currentDateTime().toString( "dd/MM/yyyy" ) + " " + CurrentTime() );
}

auto CurrentTime(
    void
) -> QString {
    return ( QTime::currentTime().toString( "hh:mm:ss" ) );
}

auto GrayScale(
    QImage image
) -> QImage {
    auto im = image.convertToFormat( QImage::Format_ARGB32 );

    for ( int y = 0; y < im.height(); ++y ) {
        auto scanLine = ( QRgb* ) im.scanLine( y );

        for ( int x = 0; x < im.width(); ++x ) {
            auto pixel = *scanLine;
            auto ci    = uint( qGray( pixel ) );

            *scanLine = qRgba( ci, ci, ci, qAlpha( pixel ) / 3 );
            ++scanLine;
        }
    }

    return im;
}