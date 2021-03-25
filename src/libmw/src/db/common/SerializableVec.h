#include <mw/serialization/Serializer.h>

class SerializableVec : public Traits::ISerializable
{
public:
    SerializableVec(std::vector<uint8_t> bytes) : m_bytes(std::move(bytes)) {}

    const std::vector<uint8_t>& Get() const { return m_bytes; }

    Serializer& Serialize(Serializer& serializer) const noexcept final
    {
        return serializer.Append(m_bytes);
    }

    static SerializableVec Deserialize(Deserializer& deserializer)
    {
        return SerializableVec(deserializer.ReadVector(deserializer.GetRemainingSize()));
    }

private:
    std::vector<uint8_t> m_bytes;
};