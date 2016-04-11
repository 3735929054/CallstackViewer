#pragma once

#include <iostream>
#include <Windows.h>
#include <string>
#include <list>

typedef struct _IAT_INFORMATION_
{
    std::string szDllName;
    std::string szFuncName;
    DWORD dwAddress;
} iatInformation;

class PEparser
{
public:
    PEparser(const char *_path = "");
    ~PEparser();
    bool parse();
    void setFilePath(const char *_path);
    DWORD convertRvaToRaw(const DWORD p);
    std::string getProcNameFromAddr(const DWORD p);

    unsigned int getNumberOfSection() const;
    IMAGE_NT_HEADERS32 getNtHeader() const;
    IMAGE_SECTION_HEADER* getSectionHeaders() const;
    IMAGE_DOS_HEADER getDosHeader() const;
    std::list<iatInformation> getIatInformationList() const;

private:
    std::string             m_filePath;
    unsigned int            m_fileSize;
    unsigned int            m_numberOfSection;
    IMAGE_NT_HEADERS32      m_ntHeader;
    IMAGE_SECTION_HEADER    *m_sectionHeaders;
    IMAGE_DOS_HEADER        m_dosHeader;
    std::list<iatInformation> m_iatList;
};