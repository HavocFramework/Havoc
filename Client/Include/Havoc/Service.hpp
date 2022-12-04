#ifndef HAVOC_SERVICE_HPP
#define HAVOC_SERVICE_HPP

#include <QString>
#include <QStringList>
#include <QJsonDocument>

#include <vector>

typedef struct
{
    QString Name;
    bool    IsFilePath;
    bool    IsOptional;
} CommandParam;

typedef struct
{
  QString Name;
  QString Extension;
} AgentFormat;

typedef struct
{
    QString                   Name;
    QString                   Description;
    QString                   Help;
    bool                      NeedAdmin;
    QStringList               Mitr;
    std::vector<CommandParam> Params;
    bool                      Anonymous;
} AgentCommands;

typedef struct
{
    QString                    Name;
    QString                    Description;
    QString                    Version;
    QString                    Author;
    uint64_t                   MagicValue;
    QStringList                Arch;
    std::vector<AgentFormat>   Formats;
    QStringList                SupportedOS;
    std::vector<AgentCommands> Commands;
    QJsonDocument              BuildingConfig;
} ServiceAgent;

extern uint64_t DemonMagicValue;

#endif
