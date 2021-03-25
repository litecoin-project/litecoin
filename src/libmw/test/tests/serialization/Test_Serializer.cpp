#include <catch.hpp>

#include <mw/serialization/Serializer.h>

TEST_CASE("Serializer")
{
    // Append<T> (BigEndian)
    {
        REQUIRE(std::vector<uint8_t>({ 0, 0, 0, 0, 73, 150, 2, 210 }) == Serializer().Append(1234567890ull).vec());
        REQUIRE(std::vector<uint8_t>({ 255, 255, 255, 255, 255, 255, 255, 202 }) == Serializer().Append(-54ll).vec());
        REQUIRE(std::vector<uint8_t>({ 73, 150, 2, 210 }) == Serializer().Append((uint32_t)1234567890ul).vec());
        REQUIRE(std::vector<uint8_t>({ 255, 255, 255, 202 }) == Serializer().Append((int32_t)-54l).vec());
        REQUIRE(std::vector<uint8_t>({ 48, 57 }) == Serializer().Append((uint16_t)12345).vec());
        REQUIRE(std::vector<uint8_t>({ 255, 202 }) == Serializer().Append((int16_t)-54).vec());
        REQUIRE(std::vector<uint8_t>({ 25 }) == Serializer().Append((uint8_t)25).vec());
        REQUIRE(std::vector<uint8_t>({ 202 }) == Serializer().Append((int8_t)-54).vec());
    }

    // AppendLE<T>
    {
        REQUIRE(std::vector<uint8_t>({ 210, 2, 150, 73, 0, 0, 0, 0 }) == Serializer().AppendLE(1234567890ull).vec());
        REQUIRE(std::vector<uint8_t>({ 202, 255, 255, 255, 255, 255, 255, 255 }) == Serializer().AppendLE(-54ll).vec());
        REQUIRE(std::vector<uint8_t>({ 210, 2, 150, 73 }) == Serializer().AppendLE((uint32_t)1234567890ul).vec());
        REQUIRE(std::vector<uint8_t>({ 202, 255, 255, 255 }) == Serializer().AppendLE((int32_t)-54l).vec());
        REQUIRE(std::vector<uint8_t>({ 57, 48 }) == Serializer().AppendLE((uint16_t)12345).vec());
        REQUIRE(std::vector<uint8_t>({ 202, 255  }) == Serializer().AppendLE((int16_t)-54).vec());
        REQUIRE(std::vector<uint8_t>({ 25 }) == Serializer().AppendLE((uint8_t)25).vec());
        REQUIRE(std::vector<uint8_t>({ 202 }) == Serializer().AppendLE((int8_t)-54).vec());
    }

    // Append(vector), Append(array)
    {
        Serializer serializer;
        serializer.Append(std::vector<uint8_t>({ 1, 2, 3 }));
        serializer.Append(std::array<uint8_t, 3>({ 4, 5, 6 }));
        REQUIRE(std::vector<uint8_t>({ 1, 2, 3, 4, 5, 6 }) == serializer.vec());
    }

    // TODO: Finish this
    // Append(const Serializable&)
    // Append(const std::shared_ptr<const Serializable>)
    // Append(const boost::optional<Serializable>&)
    // uint8_t& operator[]
    // const uint8_t& operator[]
}