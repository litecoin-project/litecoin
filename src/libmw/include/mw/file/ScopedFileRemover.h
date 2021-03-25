#pragma once

#include <mw/file/File.h>

// Removes a file when object goes out of scope
class ScopedFileRemover
{
public:
	ScopedFileRemover(const File& file) : m_path(file.GetPath()) {}
	ScopedFileRemover(const FilePath& path) : m_path(path) {}
	~ScopedFileRemover() { 
		try {
			m_path.Remove();
		}
		catch (std::exception& e) {
			std::cout << "Exception thrown in ScopedFileRemover. Path:" << m_path.ToString() << " Error: " << e.what() << std::endl;
		}
	}

private:
	FilePath m_path;
};