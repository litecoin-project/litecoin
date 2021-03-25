#pragma once

#include <mw/util/StringUtil.h>

#define ThrowFatal(msg) throw FatalException(msg, __FUNCTION__)
#define ThrowFatal_F(msg, ...) throw FatalException(StringUtil::Format(msg, __VA_ARGS__), __FUNCTION__)

class FatalException
{
public:
    FatalException(const std::string& message, const std::string& function)
        : m_message(message), m_function(function), m_what(function + ": " + message) { }

    const char* what() const noexcept { return m_what.c_str(); }
    const std::string& GetMsg() const { return m_message; }
    
private:
    std::string m_message;
    std::string m_function;
    std::string m_what;
};