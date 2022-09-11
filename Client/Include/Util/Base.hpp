#ifndef HAVOC_BASE_HPP
#define HAVOC_BASE_HPP

#include <spdlog/spdlog.h>

#include <QString>
#include <QFile>

auto FileRead( const QString& FilePath ) -> QByteArray;

#endif
