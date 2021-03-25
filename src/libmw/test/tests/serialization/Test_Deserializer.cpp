#include <catch.hpp>

#include <mw/serialization/Deserializer.h>

TEST_CASE("Deserializer")
{
    // Read<T> (Big Endian)
    {
        REQUIRE(Deserializer({ 0, 0, 0, 0, 73, 150, 2, 210 }).Read<uint64_t>() == 1234567890ull);
        REQUIRE(Deserializer({ 255, 255, 255, 255, 255, 255, 255, 202 }).Read<int64_t>() == -54ll);
        REQUIRE(Deserializer({ 73, 150, 2, 210 }).Read<uint32_t>() == 1234567890ul);
        REQUIRE(Deserializer({ 255, 255, 255, 202 }).Read<int32_t>() == -54l);
        REQUIRE(Deserializer({ 48, 57 }).Read<uint16_t>() == (uint16_t)12345);
        REQUIRE(Deserializer({ 255, 202 }).Read<int16_t>() == (int16_t)-54);
        REQUIRE(Deserializer({ 25 }).Read<uint8_t>() == (uint8_t)25);
        REQUIRE(Deserializer({ 202 }).Read<int8_t>() == (int8_t)-54);
    }

    // ReadLE<T> (Little Endian)
    {
        REQUIRE(Deserializer({ 210, 2, 150, 73, 0, 0, 0, 0 }).ReadLE<uint64_t>() == 1234567890ull);
        REQUIRE(Deserializer({ 202, 255, 255, 255, 255, 255, 255, 255 }).ReadLE<int64_t>() == -54ll);
        REQUIRE(Deserializer({ 210, 2, 150, 73 }).ReadLE<uint32_t>() == 1234567890ul);
        REQUIRE(Deserializer({ 202, 255, 255, 255 }).ReadLE<int32_t>() == -54l);
        REQUIRE(Deserializer({ 57, 48 }).ReadLE<uint16_t>() == (uint16_t)12345);
        REQUIRE(Deserializer({ 202, 255 }).ReadLE<int16_t>() == (int16_t)-54);
        REQUIRE(Deserializer({ 25 }).ReadLE<uint8_t>() == (uint8_t)25);
        REQUIRE(Deserializer({ 202 }).ReadLE<int8_t>() == (int8_t)-54);
    }

    // TODO: ReadVec, ReadVector, ReadArray, ReadOpt
}