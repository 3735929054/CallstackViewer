#pragma once

#include <iostream>
#include <Windows.h>
#include <string>

class PEparser
{
public:
    PEparser(const char *_path = "");
    bool parse();
    IMAGE_NT_HEADERS32 getNtHeader();
    IMAGE_SECTION_HEADER* getSectionHeaders();
    IMAGE_DOS_HEADER getDosHeader();
    unsigned int getNumberOfSection();
    void setFilePath(const char *_path);

private:
    std::string             m_filePath;
    unsigned int            m_fileSize;
    unsigned int            m_numberOfSection;
    IMAGE_NT_HEADERS32      m_ntHeader;
    IMAGE_SECTION_HEADER    *m_sectionHeaders;
    IMAGE_DOS_HEADER        m_dosHeader;
};