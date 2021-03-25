#pragma once

#include <mw/exceptions/LTCException.h>
#include <mw/util/StringUtil.h>

#define ThrowUnimplemented(msg) throw UnimplementedException(msg, __FUNCTION__)
#define ThrowUnimplemented_F(msg, ...) throw UnimplementedException(StringUtil::Format(msg, __VA_ARGS__), __FUNCTION__)

class UnimplementedException : public LTCException
{
public:
    UnimplementedException(const std::string& message, const std::string& function)
        : LTCException("UnimplementedException", message, function)
    {

    }
};