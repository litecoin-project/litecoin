#include <mw/file/File.h>
#include <mw/common/Logger.h>
#include <fs.h>
#include <util/system.h>

#include <cerrno>

#if defined(_WIN32)
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace
{
void CommitParentDirectory(const FilePath& path)
{
#if defined(_WIN32)
    HANDLE hDirectory = CreateFileW(
        path.ToBoost().wstring().c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr
    );
    if (hDirectory == INVALID_HANDLE_VALUE) {
        ThrowFile_F("Failed to open directory for syncing: {}", path);
    }

    if (FlushFileBuffers(hDirectory) == 0) {
        const DWORD error = GetLastError();
        CloseHandle(hDirectory);
        if (error != ERROR_ACCESS_DENIED && error != ERROR_INVALID_FUNCTION) {
            ThrowFile_F("Failed to sync directory: {}", path);
        }
        return;
    }

    CloseHandle(hDirectory);
#else
    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif

    const int fd = open(path.ToString().c_str(), flags);
    if (fd < 0) {
        ThrowFile_F("Failed to open directory for syncing: {}", path);
    }

    if (fsync(fd) != 0 && errno != EINVAL) {
        close(fd);
        ThrowFile_F("Failed to sync directory: {}", path);
    }

    close(fd);
#endif
}
}

void File::Create()
{
    m_path.GetParent().CreateDir();

    std::ifstream inFile(m_path.m_path, std::ios::in | std::ifstream::ate | std::ifstream::binary);
    if (inFile.is_open()) {
        inFile.close();
    } else {
        LOG_INFO_F("File {} does not exist. Creating it now.", m_path);
        std::ofstream outFile(m_path.m_path, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!outFile.is_open()) {
            ThrowFile_F("Failed to create file: {}", m_path);
        }
        outFile.close();
    }
}

bool File::Exists() const
{
    return m_path.Exists() && !m_path.IsDirectory();
}

void File::Truncate(const uint64_t size)
{
    bool success = false;

#if defined(WIN32)
    HANDLE hFile = CreateFile(
        m_path.ToString().c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    LARGE_INTEGER li;
    li.QuadPart = size;
    success = SetFilePointerEx(hFile, li, NULL, FILE_BEGIN) && SetEndOfFile(hFile);

    CloseHandle(hFile);
#else
    success = (truncate(m_path.ToString().c_str(), size) == 0);
#endif

    if (!success) {
        ThrowFile_F("Failed to truncate {}", m_path);
    }
}

std::vector<uint8_t> File::ReadBytes() const
{
    std::error_code ec;
    if (!ghc::filesystem::exists(m_path.m_path, ec) || ec) {
        ThrowFile_F("{} not found", *this);
    }

    size_t size = (size_t)ghc::filesystem::file_size(m_path.m_path, ec);

    return ReadBytes(0, size);
}

std::vector<uint8_t> File::ReadBytes(const size_t startIndex, const size_t numBytes) const
{
    std::error_code ec;
    if (!ghc::filesystem::exists(m_path.m_path, ec) || ec) {
        ThrowFile_F("{} not found", *this);
    }

    std::ifstream file(m_path.m_path, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        ThrowFile_F("Failed to open {} for reading", *this);
    }

    const size_t size = (size_t)ghc::filesystem::file_size(m_path.m_path, ec);
    if (size < (startIndex + numBytes)) {
        ThrowFile_F("Failed to read {} bytes from {}.", numBytes, *this);
    }

    std::vector<uint8_t> bytes(numBytes);
    file.seekg(startIndex, std::ios::beg);
    file.read((char*)bytes.data(), numBytes);
    file.close();

    return bytes;
}

void File::Write(const std::vector<uint8_t>& bytes)
{
    if (!Exists()) {
        Create();
    }

    std::ofstream file(m_path.m_path, std::ios::out | std::ios::binary | std::ios::app);
    if (!file.is_open()) {
        ThrowFile_F("Failed to write to file: {}", m_path);
    }

    file.write((const char*)bytes.data(), bytes.size());
    file.close();
}

void File::Write(const size_t startIndex, const std::vector<uint8_t>& bytes, const bool truncate)
{
    if (!Exists()) {
        Create();
    }
    
    if (!bytes.empty()) {
        std::fstream file(m_path.m_path, std::ios::in | std::ios::out | std::ios::binary);
        if (!file.is_open()) {
            ThrowFile_F("Failed to write to file: {}", m_path);
        }

        file.seekp(startIndex, std::ios::beg);
        file.write((const char*)bytes.data(), bytes.size());
        file.close();
    }

    if (truncate) {
        Truncate(startIndex + bytes.size());
    }
}

void File::WriteBytes(const std::unordered_map<uint64_t, uint8_t>& bytes)
{
    std::fstream file(m_path.m_path, std::ios_base::binary | std::ios_base::out | std::ios_base::in);

    for (auto iter : bytes) {
        file.seekp(iter.first);
        file.write((const char*)&iter.second, 1);
    }

    file.close();
}

void File::Commit() const
{
    FILE* file = fsbridge::fopen(m_path.ToBoost(), "rb");
    if (file == nullptr) {
        ThrowFile_F("Failed to open {} for syncing", *this);
    }

    if (!FileCommit(file)) {
        fclose(file);
        ThrowFile_F("Failed to sync {}", *this);
    }

    fclose(file);

    if (m_path.m_path.has_parent_path()) {
        CommitParentDirectory(m_path.GetParent());
    }
}

size_t File::GetSize() const
{
    if (!m_path.Exists()) {
        return 0;
    }

    std::error_code ec;
    const size_t size = (size_t)ghc::filesystem::file_size(m_path.m_path, ec);
    if (ec) {
        ThrowFile_F("Failed to determine size of {}", *this);
    }

    return size;
}

void File::CopyTo(const FilePath& new_path) const
{
    if (new_path.Exists()) {
        new_path.Remove();
    }

    std::error_code ec;
    ghc::filesystem::copy(m_path.m_path, new_path.m_path, ec);
    if (ec) {
        ThrowFile_F("Failed to copy {} to {}", m_path, new_path);
    }
}
