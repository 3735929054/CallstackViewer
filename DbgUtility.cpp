#include "DbgUtility.h"

#include <TlHelp32.h>
#include <wchar.h>
#include <Windows.h>
#include <Psapi.h>
#include <tchar.h>

#define BUFSIZE 512

DbgUtility::DbgUtility(std::string file_name)
{
    ZeroMemory(&m_procInfo, sizeof(m_procInfo));
    ZeroMemory(&m_startInfo, sizeof(m_startInfo));
    m_targetFileName = file_name;
}

DbgUtility::~DbgUtility()
{
    if (NULL != m_procInfo.hProcess)
    {
        CloseHandle(m_procInfo.hProcess);
        CloseHandle(m_procInfo.hThread);
    }
}

HANDLE DbgUtility::GetWindowsHandle()
{
    return m_procInfo.hProcess;
}

bool DbgUtility::doDebuggerProc()
{
    if (DbgUtility::doDebuggerProc(m_targetFileName, m_procInfo, m_startInfo)) return true;
    else return false;
}

void DbgUtility::setTargetFileName(const char *file_name)
{
    m_targetFileName = file_name;
}

void DbgUtility::setTargetFileName(std::string& file_name)
{
    m_targetFileName = file_name;
}

std::string DbgUtility::GetTargetFileName()
{
    return m_targetFileName;
}

bool DbgUtility::checkRemoteDbgPresent(HANDLE hProc)
{
    BOOL debug_state = false;
    CheckRemoteDebuggerPresent(hProc, &debug_state);

    return (debug_state) ? true : false;
}

DWORD DbgUtility::getProcessIdFromeName(std::string& process_name)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    PROCESSENTRY32 pe32 = { 0, };
    pe32.dwSize = sizeof(pe32);

    if (hSnapshot == INVALID_HANDLE_VALUE) return NULL;
    if (!Process32First(hSnapshot, &pe32))
    {
        CloseHandle(hSnapshot);
        return NULL;
    }

    do
    {
        if (!process_name.compare(pe32.szExeFile)) return pe32.th32ProcessID;
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return NULL;
}

HANDLE DbgUtility::getWindowsHandleFromeName(std::string& process_name)
{
    const DWORD target_process_id = DbgUtility::getProcessIdFromeName(process_name);
    HANDLE  temporary_wnd_handle = FindWindow(NULL, NULL);
    DWORD   temporary_process_id = 0;

    while (temporary_wnd_handle != NULL)
    {
        GetWindowThreadProcessId(static_cast<HWND>(temporary_wnd_handle), &temporary_process_id);
        if (target_process_id == temporary_process_id)
        {
            return temporary_wnd_handle;
        }
        temporary_wnd_handle = GetWindow(static_cast<HWND>(temporary_wnd_handle), GW_HWNDNEXT);
    }

    return NULL;
}

bool DbgUtility::doDebuggerProc(std::string& file_name, PROCESS_INFORMATION& process_info, STARTUPINFO& startup_info)
{
    struct stat stat_buf;

    if (stat(file_name.c_str(), &stat_buf) == 0)
    {
        // 프로세스 생성
        if (!CreateProcessA(file_name.c_str(),
            NULL,
            NULL,
            NULL,
            FALSE,
            DEBUG_PROCESS,
            NULL,
            NULL,
            &startup_info,
            &process_info))
        {
            DbgUtility::dbgPrint("CreateProcess() Failed!");
            return false; // 프로세스의 생성을 실패했을 때.
        }

        DEBUG_EVENT dbgEvent;
        ZeroMemory(&dbgEvent, sizeof(dbgEvent));
        while (true)
        {
            if (!WaitForDebugEvent(&dbgEvent, INFINITE))
            {
                DbgUtility::dbgPrint("Failed WaitForDebugEvent()!");
                return false;
            }

            switch (dbgEvent.dwDebugEventCode)
            {
            case CREATE_PROCESS_DEBUG_EVENT:
                DbgUtility::dbgPrint("CREATE_PROCESS_DEBUG_EVENT");
                break;
            case LOAD_DLL_DEBUG_EVENT:
                if (dbgEvent.u.LoadDll.hFile)
                {
                    char szFilePath[MAX_PATH] = { 0, };
                    char *pszFileName = nullptr;
                    strcpy_s(szFilePath, sizeof(szFilePath), DbgUtility::getFileNameFromeHandle(dbgEvent.u.LoadDll.hFile).c_str());
                    for (int i = strlen(szFilePath); i > 0; --i)
                        if ('\\' == szFilePath[i] || '/' == szFilePath[i])
                        {
                            pszFileName = &szFilePath[i + 1];
                            break;
                        }
                    DbgUtility::dbgPrint(pszFileName);
                }
                break;
            case EXIT_PROCESS_DEBUG_EVENT:
                return true; // 프로세스가 종료 되었을 때.
            default:
                break;
            }
            ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
        }
    }
    return false; // 파일이 없을 경우.
}

void DbgUtility::dbgPrint(const char *format, ...)
{
    va_list arg_list;
    va_start(arg_list, format);
    char tmp[2000] = { 0, };
    wsprintf(tmp, format, arg_list);
    OutputDebugString(tmp);
}

void DbgUtility::dbgPrint(const wchar_t *format, ...)
{
    va_list arg_list;
    va_start(arg_list, format);
    wchar_t tmp[2000] = { 0, };
    wsprintfW(tmp, format, arg_list);
    OutputDebugStringW(tmp);
}

//Ref* https://msdn.microsoft.com/ko-kr/library/windows/desktop/aa366789(v=vs.85).aspx
std::string DbgUtility::getFileNameFromeHandle(HANDLE hFile)
{
    bool bSuccess = false;
    TCHAR pszFilename[MAX_PATH + 1];
    HANDLE hFileMap;

    // Get the file size.
    DWORD dwFileSizeHi = 0;
    DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi);

    if (dwFileSizeLo == 0 && dwFileSizeHi == 0)
    {
        return "(unknown)";
    }

    // Create a file mapping object.
    hFileMap = CreateFileMapping(hFile,
        NULL,
        PAGE_READONLY,
        0,
        1,
        NULL);

    if (hFileMap)
    {
        // Create a file mapping to get the file name.
        void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);

        if (pMem)
        {
            if (GetMappedFileName(GetCurrentProcess(),
                pMem,
                pszFilename,
                MAX_PATH))
            {

                // Translate path with device name to drive letters.
                TCHAR szTemp[BUFSIZE];
                szTemp[0] = '\0';

                if (GetLogicalDriveStrings(BUFSIZE - 1, szTemp))
                {
                    TCHAR szName[MAX_PATH];
                    TCHAR szDrive[3] = TEXT(" :");
                    BOOL bFound = FALSE;
                    TCHAR* p = szTemp;

                    do
                    {
                        // Copy the drive letter to the template string
                        *szDrive = *p;

                        // Look up each device name
                        if (QueryDosDevice(szDrive, szName, MAX_PATH))
                        {
                            size_t uNameLen = _tcslen(szName);

                            if (uNameLen < MAX_PATH)
                            {
                                bFound = _tcsnicmp(pszFilename, szName, uNameLen) == 0
                                    && *(pszFilename + uNameLen) == _T('\\');

                                if (bFound)
                                {
                                    // Reconstruct pszFilename using szTempFile
                                    // Replace device path with DOS path
                                    TCHAR szTempFile[MAX_PATH];
                                    _stprintf_s(szTempFile,
                                        TEXT("%s%s"),
                                        szDrive,
                                        pszFilename + uNameLen);
                                    _tcsncpy_s(pszFilename, szTempFile, _tcslen(szTempFile));
                                }
                            }
                        }

                        // Go to the next NULL character.
                        while (*p++);
                    } while (!bFound && *p); // end of string
                }
            }
            bSuccess = TRUE;
            UnmapViewOfFile(pMem);
        }

        CloseHandle(hFileMap);
    }

    return(pszFilename);
}