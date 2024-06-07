//     Copyright Toru Niina 2017.
// Distributed under the MIT License.
#ifndef TOML11_EXCEPTION_HPP
#define TOML11_EXCEPTION_HPP

#include <array>
#include <string>
#include <stdexcept>
#include <cstring>

#include "source_location.hpp"

namespace toml
{

namespace detail
{

inline std::string str_error(int errnum)
{
    // C++ standard strerror is not thread-safe.
    // C11 provides thread-safe version of this function, `strerror_s`, but it
    // is not available in C++.
    // To avoid using std::strerror, we need to use platform-specific functions.
    // If none of the conditions are met, it calls std::strerror as a fallback.

#ifdef _MSC_VER // MSVC
    constexpr std::size_t bufsize = 256;
    std::array<char, bufsize> buf;
    buf.fill('\0');
    const auto result = strerror_s(buf.data(), bufsize, errnum);
    if(result != 0)
    {
        return std::string("strerror_s failed");
    }
    else
    {
        return std::string(buf.data());
    }
#elif defined(__APPLE__) && defined(__MACH__) // macOS
    constexpr std::size_t bufsize = 256;
    std::array<char, bufsize> buf;
    buf.fill('\0');
    if (strerror_r(errnum, buf.data(), bufsize) != 0)
    {
        return std::string("strerror_r failed");
    }
    else
    {
        return std::string(buf.data());
    }
#elif defined(_GNU_SOURCE) // GNU-specific strerror_r
    constexpr std::size_t bufsize = 256;
    std::array<char, bufsize> buf;
    buf.fill('\0');
    char* result = strerror_r(errnum, buf.data(), bufsize);
    return std::string(result);
#elif (defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L) || (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE >= 600) // POSIX
    constexpr std::size_t bufsize = 256;
    std::array<char, bufsize> buf;
    buf.fill('\0');
    if (strerror_r(errnum, buf.data(), bufsize) != 0)
    {
        return std::string("strerror_r failed");
    }
    else
    {
        return std::string(buf.data());
    }
#else // fallback
    return std::strerror(errnum);
#endif
}

} // detail

struct file_io_error : public std::runtime_error
{
  public:
    file_io_error(int errnum, const std::string& msg, const std::string& fname)
        : std::runtime_error(msg + " \"" + fname + "\": " + detail::str_error(errnum)),
          errno_(errnum)
    {}
    int get_errno() const noexcept {return errno_;}

  private:
    int errno_;
};

struct exception : public std::exception
{
  public:
    explicit exception(const source_location& loc): loc_(loc) {}
    virtual ~exception() noexcept override = default;
    virtual const char* what() const noexcept override {return "";}
    virtual source_location const& location() const noexcept {return loc_;}

  protected:
    source_location loc_;
};

struct syntax_error : public toml::exception
{
  public:
    explicit syntax_error(const std::string& what_arg, const source_location& loc)
        : exception(loc), what_(what_arg)
    {}
    virtual ~syntax_error() noexcept override = default;
    virtual const char* what() const noexcept override {return what_.c_str();}

  protected:
    std::string what_;
};

struct type_error : public toml::exception
{
  public:
    explicit type_error(const std::string& what_arg, const source_location& loc)
        : exception(loc), what_(what_arg)
    {}
    virtual ~type_error() noexcept override = default;
    virtual const char* what() const noexcept override {return what_.c_str();}

  protected:
    std::string what_;
};

struct internal_error : public toml::exception
{
  public:
    explicit internal_error(const std::string& what_arg, const source_location& loc)
        : exception(loc), what_(what_arg)
    {}
    virtual ~internal_error() noexcept override = default;
    virtual const char* what() const noexcept override {return what_.c_str();}

  protected:
    std::string what_;
};

} // toml
#endif // TOML_EXCEPTION
