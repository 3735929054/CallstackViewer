#include "PEparser.h"

PEparser::PEparser(const char *_path)
{
    m_filePath = _path;
    m_fileSize = 0;

    ZeroMemory(&m_dosHeader, sizeof(m_dosHeader));
    ZeroMemory(&m_sectionHeaders, sizeof(m_sectionHeaders));
    ZeroMemory(&m_ntHeader, sizeof(m_ntHeader));
}

PEparser::~PEparser()
{
}

unsigned int PEparser::getNumberOfSection()
{
    return m_numberOfSection;
}

void PEparser::setFilePath(const char *_path)
{
    m_filePath = _path;
}

bool PEparser::parse()
{
    if (0 >= m_filePath.length()) return false;

    FILE *in;
    if (fopen_s(&in, m_filePath.c_str(), "rb"))
        return false;

    // Get file size
    fseek(in, 0, SEEK_END);
    m_fileSize = ftell(in);
    rewind(in);

    BYTE *fileBuffer = new BYTE[m_fileSize];
    // Save file headers in PeBuffer
    fread_s(fileBuffer, m_fileSize, m_fileSize, 1, in);

    memcpy_s(&m_dosHeader, sizeof(m_dosHeader), fileBuffer, sizeof(m_dosHeader));
    memcpy_s(&m_ntHeader, sizeof(m_ntHeader), (fileBuffer + m_dosHeader.e_lfanew), sizeof(m_ntHeader));

    m_numberOfSection = m_ntHeader.FileHeader.NumberOfSections;
    m_sectionHeaders = new IMAGE_SECTION_HEADER[m_numberOfSection];
    unsigned int offset = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32);
    for (int i = 0; i < m_numberOfSection; ++i)
    {
        memcpy_s(
            &m_sectionHeaders[i],
            sizeof(IMAGE_SECTION_HEADER),
            (fileBuffer + (m_dosHeader.e_lfanew + offset + (sizeof(IMAGE_SECTION_HEADER) * i))),
            sizeof(IMAGE_SECTION_HEADER));
    }

    // IAT
    DWORD dwImportDirectoryTableOffset = convertRvaToRaw(m_ntHeader.OptionalHeader.DataDirectory[1].VirtualAddress);
    UINT nImportTableSize = (m_ntHeader.OptionalHeader.DataDirectory[1].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR)) - 1/*remove NULL data count*/;
    IMAGE_IMPORT_DESCRIPTOR *arrDescriptor = new IMAGE_IMPORT_DESCRIPTOR[nImportTableSize];
    // copy import decriptor section.
    for (int i = 0; i < nImportTableSize; ++i)
    {
        memcpy_s(
            &arrDescriptor[i],
            sizeof(IMAGE_IMPORT_DESCRIPTOR),
            (fileBuffer + dwImportDirectoryTableOffset) + (sizeof(IMAGE_IMPORT_DESCRIPTOR) * i),
            sizeof(IMAGE_IMPORT_DESCRIPTOR));
    }

    for (int i = 0; i < nImportTableSize; ++i)
    {
        DWORD dwRawDllNameAddr = convertRvaToRaw(arrDescriptor[i].Name);
        std::string strDllname = (char*)&fileBuffer[dwRawDllNameAddr]; // save data
        auto hModule= GetModuleHandleA(strDllname.c_str());

        int idx = 0;
        while (true)
        {
            DWORD dwRawImportNameTableOffset = convertRvaToRaw(arrDescriptor[i].OriginalFirstThunk + (sizeof(DWORD) * idx));
            DWORD dwRawImportNameData = *(DWORD*)&fileBuffer[dwRawImportNameTableOffset];

            if (!memcmp(&dwRawImportNameData, "\x00\x00\x00", 4)) break; // NULL field -> break;
            else dwRawImportNameData = convertRvaToRaw(dwRawImportNameData);

            std::string strFunctionName = (char*)&fileBuffer[dwRawImportNameData + 2/*bypass HINT field*/]; // save data
            DWORD dwFuncAddr = (DWORD)GetProcAddress(hModule, strFunctionName.c_str());
            iatInformation tmp = { strDllname, strFunctionName, dwFuncAddr };
            m_iatList.push_back(tmp);

            idx++; // next import name table
        }
    }

    delete[] fileBuffer;
    fclose(in);

    return true;
}

IMAGE_NT_HEADERS PEparser::getNtHeader()
{
    return m_ntHeader;
}

IMAGE_DOS_HEADER PEparser::getDosHeader()
{
    return m_dosHeader;
}

IMAGE_SECTION_HEADER* PEparser::getSectionHeaders()
{
    return m_sectionHeaders;
}

DWORD PEparser::convertRvaToRaw(const DWORD p)
{
    // p에 해당하는 섹션을 검색 후 rav to raw
    for (int i = 0; i < (m_numberOfSection - 1); ++i)
    {
        if (m_sectionHeaders[i].VirtualAddress <= p)
        {
            if (m_sectionHeaders[i + 1].VirtualAddress >= p)
            {
                return (p - m_sectionHeaders[i].VirtualAddress + m_sectionHeaders[i].PointerToRawData);
            }
        }
    }

    // 마지막 섹션에 위치한 p에 대한 rva to raw
    if (m_sectionHeaders[m_numberOfSection - 1].VirtualAddress <= p)
    {
        return (p - m_sectionHeaders[m_numberOfSection - 1].VirtualAddress + m_sectionHeaders[m_numberOfSection - 1].PointerToRawData);
    }

    return 0;
}

std::list<iatInformation> PEparser::getIatInformationList()
const
{
    return m_iatList;
}

std::string PEparser::getProcNameWidthAddr(const DWORD p)
{
    auto iter = m_iatList.begin();
    while (iter != m_iatList.end())
    {
        if (iter->dwAddress == p)
            return iter->szFuncName;
        iter++;
    }
    return "(unknown)";
}