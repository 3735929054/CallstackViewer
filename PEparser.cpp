#include "PEparser.h"

PEparser::PEparser(const char *_path)
{
    m_filePath = _path;
    m_fileSize = 0;
    ZeroMemory(&m_dosHeader, sizeof(m_dosHeader));
    ZeroMemory(&m_sectionHeaders, sizeof(m_sectionHeaders));
    ZeroMemory(&m_ntHeader, sizeof(m_ntHeader));
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
        return EXIT_FAILURE;

    BYTE fileBuffer[1024];
    // Save file header in PeBuffer
    fread_s(fileBuffer, 1024, 1024, 1, in);
    // Get file size
    fseek(in, 0, SEEK_END);
    m_fileSize = ftell(in);
    rewind(in);

    memcpy_s(&m_dosHeader, sizeof(m_dosHeader), fileBuffer, sizeof(m_dosHeader));
    memcpy_s(&m_dosHeader, sizeof(m_dosHeader), (fileBuffer + m_dosHeader.e_lfanew), sizeof(m_dosHeader));

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
    fclose(in);
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