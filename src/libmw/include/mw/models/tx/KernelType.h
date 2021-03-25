#pragma once

#include <mw/exceptions/DeserializationException.h>
#include <cstdint>

struct KernelType
{
    enum EKernelType : uint8_t
    {
        // No flags
        PLAIN_KERNEL = 0,

        // Pegged-in kernel
        PEGIN_KERNEL = 1,

        // Pegged-out kernel
        PEGOUT_KERNEL = 2,

        // Height-locked kernel
        HEIGHT_LOCKED = 3
    };

    static EKernelType FromString(const std::string& type)
    {
        if (type == "PLAIN")
        {
            return EKernelType::PLAIN_KERNEL;
        }
        else if (type == "PEGIN")
        {
            return EKernelType::PEGIN_KERNEL;
        }
        else if (type == "PEGOUT")
        {
            return EKernelType::PEGOUT_KERNEL;
        }
        else if (type == "HEIGHT_LOCKED")
        {
            return EKernelType::HEIGHT_LOCKED;
        }

        ThrowDeserialization_F("Unknown kernel type: {}", type);
    }

    static std::string ToString(const uint8_t type)
    {
        switch ((EKernelType)type)
        {
            case PLAIN_KERNEL:
                return "PLAIN";
            case PEGIN_KERNEL:
                return "PEGIN";
            case PEGOUT_KERNEL:
                return "PEGOUT";
            case HEIGHT_LOCKED:
                return "HEIGHT_LOCKED";
            default:
                return "UNKNOWN";
        }
    }
};