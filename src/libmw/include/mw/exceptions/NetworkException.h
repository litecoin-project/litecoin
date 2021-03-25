#pragma once

#include <mw/exceptions/LTCException.h>
#include <mw/util/StringUtil.h>

#define ThrowNetwork(msg) throw NetworkException(msg, __FUNCTION__)
#define ThrowNetwork_F(msg, ...) throw NetworkException(StringUtil::Format(msg, __VA_ARGS__), __FUNCTION__)

class NetworkException : public LTCException
{
public:
    NetworkException(const std::string& message, const std::string& function)
        : LTCException("NetworkException", message, function)
    {

    }
};