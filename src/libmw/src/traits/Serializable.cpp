#include <mw/traits/Serializable.h>
#include <mw/serialization/Serializer.h>

namespace Traits
{
    std::vector<uint8_t> ISerializable::Serialized() const noexcept
    {
        Serializer serializer;
        Serialize(serializer);
        return serializer.vec();
    }
}