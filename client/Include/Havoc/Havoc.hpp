#ifndef HAVOC_HAVOC_HPP
#define HAVOC_HAVOC_HPP

#include <global.hpp>
#include <UserInterface/HavocUI.hpp>
#include <Havoc/DBManager/DBManager.hpp>

using namespace HavocNamespace;

class HavocSpace::Havoc {
public:
    UserInterface::HavocUI HavocAppUI;
    DBManager* dbManager;
    QMainWindow* HavocMainWindow;
    bool ClientInitConnect = true;

    Havoc( QMainWindow* );
    ~Havoc();

    void Init( int argc, char** argv );
    void Start();

    static void Exit();
};

#endif
