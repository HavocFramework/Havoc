/*#include <include/Havoc/Arguments/Arguments.hpp>
#include <spdlog/spdlog.h>
#include <iostream>

HavocArgOptions::HavocArgOptions(int argc, char** argv)
{
    namespace options = boost::program_options;

    options::options_description description("Available options");

    description.add_options()
            ("help", options::bool_switch(), "Show this help menu")
            ("teamserver-host", options::value<std::string>(), "Teamserver Host IP to connect to")
            ("teamserver-port", options::value<std::string>(), "Teamserver Port to connect to")

            ("debug", options::bool_switch(), "enable debug information");

    options::store(options::parse_command_line(argc, argv, description), this->ArgumentsMap);

    if ( GetBool("debug") )
        spdlog::info("Arguments specified: {}", ArgumentsMap.size());

    try {
        options::notify(ArgumentsMap);
    } catch (std::exception& e) {
        spdlog::error("{}",e.what());
        std::cout << description << std::endl;
        return;
    }

    if ( ArgumentsMap["help"].as<bool>() )
    {
        std::cout << description << std::endl;
        exit(0);
    }

}

bool HavocArgOptions::GetBool(const std::string& flag) const
{
    return ArgumentsMap[flag].as<bool>();
}

std::string HavocArgOptions::GetString(const std::string& flag) const
{
    return ArgumentsMap[flag].as<std::string>();
}

int HavocArgOptions::GetInteger(const std::string& flag) const
{
    return ArgumentsMap[flag].as<int>();
}

*/