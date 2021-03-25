#pragma once

#include <mw/file/FilePath.h>
#include <mw/traits/Printable.h>
#include <unordered_map>

class File : public Traits::IPrintable
{
public:
    File(const FilePath& path) : m_path(path) { }
    File(FilePath&& path) : m_path(std::move(path)) { }
    virtual ~File() = default;

    // Creates an empty file if it doesn't already exist
    void Create();

    bool Exists() const;
    void Truncate(const uint64_t size);
    void Rename(const std::string& filename);
    std::vector<uint8_t> ReadBytes() const;
    std::vector<uint8_t> ReadBytes(const size_t startIndex, const size_t numBytes) const;
    void Write(const std::vector<uint8_t>& bytes);
    void Write(
        const size_t startIndex,
        const std::vector<uint8_t>& bytes,
        const bool truncate
    );
    void WriteBytes(const std::unordered_map<uint64_t, uint8_t>& bytes);
    size_t GetSize() const;

    void CopyTo(const FilePath& new_path) const;

    const FilePath& GetPath() const noexcept { return m_path; }
    const filesystem::path& GetFSPath() const noexcept { return m_path.GetFSPath(); }

    //
    // Traits
    //
    std::string Format() const final { return m_path.u8string(); }

private:
    FilePath m_path;
};