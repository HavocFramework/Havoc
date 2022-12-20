#ifndef HAVOC_PACK_HPP
#define HAVOC_PACK_HPP

#include <global.hpp>
#include <vector>

class HavocNamespace::Util::Pack {
private:
    std::vector<unsigned char> Arguments;

public:
    Pack();
    ~Pack();

    void addInt(int);
    void addString(const std::string&);
    void addBytes(unsigned char* bytes, int len);
    unsigned char* Generate();
};

#endif
