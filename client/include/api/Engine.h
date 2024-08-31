#ifndef HAVOCCLIENT_API_ENGINE_H
#define HAVOCCLIENT_API_ENGINE_H

#include <Common.h>

#include <api/HcCore.h>
#include <api/HcScriptManager.h>
#include <api/HcAgent.h>
#include <api/HcListener.h>

class HcPyEngine {
    PyThreadState* state = { 0 };

public:
    py11::scoped_interpreter* guard{};

    std::optional<py11::object> PyEval = {};
    std::optional<py11::object> PyLoad = {};

    explicit HcPyEngine();
    ~HcPyEngine();
};

#endif
