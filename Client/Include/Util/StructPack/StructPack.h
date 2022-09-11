#ifndef HAVOC_STRUCTPACK_H
#define HAVOC_STRUCTPACK_H

#include <global.hpp>
#include <vector>
#include <Util/StructPack/struct.h>

using namespace std;

class HavocNamespace::Util::StructPack {
    // TODO: finish this
private:
    string Arguments = "";

public:
    void addString(string str) {

        char buffer[str.length() + 1];
        memset(buffer, 0, str.length() + 1);
        char fmt[BUFSIZ] = { 0 };

        snprintf(fmt, sizeof(fmt), "<L%ds", str.length());
        int size = struct_pack(buffer, fmt, str.c_str());

        this->addInt(str.length());
        this->Arguments.insert(this->Arguments.end(), str.begin(), str.end());
    };

    void addInt(int dint) {
        char integerBuffer[BUFSIZ] = { 0 };
        int size = struct_pack(integerBuffer, "<i", dint);

        this->Arguments.insert(this->Arguments.end(), integerBuffer, integerBuffer+size);
    };

    void addShort(uint16_t dshort) {

    };

    string generate() {
        return Arguments;
    };
};

#endif
