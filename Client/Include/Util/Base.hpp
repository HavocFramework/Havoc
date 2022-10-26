#ifndef HAVOC_BASE_HPP
#define HAVOC_BASE_HPP

#include <spdlog/spdlog.h>

#include <QString>
#include <QFile>
#include <QIcon>
#include <QMessageBox>

auto FileRead( const QString& FilePath ) -> QByteArray;
auto MessageBox( QString Title, QString Text, QMessageBox::Icon Icon ) -> void;
auto WinVersionIcon( QString OSVersion, bool High ) -> QIcon;
auto WinVersionImage( QString OSVersion, bool High ) -> QImage;
auto GrayScale( QImage image ) -> QImage;

#endif
