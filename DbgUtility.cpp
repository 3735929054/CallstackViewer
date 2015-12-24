#include "DbgUtility.h"

#include <TlHelp32.h>
#include <wchar.h>
#include <Windows.h>
#include <Psapi.h>
#include <tchar.h>

// macro
#define BUFSIZE 512

// functions
DbgUtility::DbgUtility(std::string file_name)
{
    ZeroMemory(&m_procInfo, sizeof(m_procInfo));
    ZeroMemory(&m_startInfo, sizeof(m_startInfo));

    onBreakpoint = nullptr;
    onCreateProcess = nullptr;
    onExitProcess = nullptr;
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
    struct stat statBuf;
    if (stat(m_targetFileName.c_str(), &statBuf) == 0)
    {
        // 프로세스 생성
        if (!CreateProcessA(
            m_targetFileName.c_str(),
            NULL,
            NULL,
            NULL,
            FALSE,
            DEBUG_ONLY_THIS_PROCESS,
            NULL,
            NULL,
            &m_startInfo,
            &m_procInfo))
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
                DbgUtility::dbgPrint("WaitForDebugEvent() Failed !");
                return false;
            }

            switch (dbgEvent.dwDebugEventCode)
            {
            case EXCEPTION_DEBUG_EVENT:
                switch (dbgEvent.u.Exception.ExceptionRecord.ExceptionCode)
                {
                case EXCEPTION_BREAKPOINT:
                    CONTEXT context;
                    context.ContextFlags = CONTEXT_ALL;
                    GetThreadContext(m_procInfo.hThread, &context);
                    context.Eip--;
                    SetThreadContext(m_procInfo.hThread, &context);

                    if (nullptr != onBreakpoint) onBreakpoint();
                    break;
                default:
                    break;
                }
                break;
            case CREATE_THREAD_DEBUG_EVENT:
                DbgUtility::dbgPrint(
                    "[CREATED] Thread 0x%x(0x%x) at 0x%x",
                    dbgEvent.u.CreateThread.hThread,
                    dbgEvent.dwThreadId,
                    dbgEvent.u.CreateThread.lpStartAddress);
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

                    loadDllInfo dllInfo = { pszFileName, dbgEvent.u.LoadDll.lpBaseOfDll };
                    DbgUtility::dbgPrint("[LOADED] %s at %x", dllInfo.pName, dllInfo.lpBaseAddr);
                    loadDllList.push_back(dllInfo);
                }
                break;
            case UNLOAD_DLL_DEBUG_EVENT:
                // unload된 dll의 주소값을 이용해 이름 찾기.
                for (auto iter = loadDllList.begin(); iter != loadDllList.end(); ++iter)
                {
                    if (iter->lpBaseAddr == dbgEvent.u.UnloadDll.lpBaseOfDll)
                    {
                        DbgUtility::dbgPrint("[UNLOADED] %s at %x", iter->pName, iter->lpBaseAddr);
                        loadDllList.erase(iter);
                        break;
                    }
                }
                break;
            case CREATE_PROCESS_DEBUG_EVENT:
                if (nullptr != onCreateProcess) onCreateProcess();
                DbgUtility::dbgPrint("CREATE_PROCESS_DEBUG_EVENT");
                break;
            case EXIT_PROCESS_DEBUG_EVENT:
                if (nullptr != onExitProcess) onExitProcess();
                DbgUtility::dbgPrint("EXIT_PROCESS_DEBUG_EVENT");
                return true; // 프로세스가 종료 되었을 때.
            default:
                break;
            }
            ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
        }
    }
    return false; // 파일이 없을 경우.
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
    BOOL bDbgState = false;
    CheckRemoteDebuggerPresent(hProc, &bDbgState);

    return (bDbgState) ? true : false;
}

DWORD DbgUtility::getProcessIdFromeName(std::string& process_name)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    PROCESSENTRY32 pe32 = { 0, };
    pe32.dwSize = sizeof(pe32);

    if (hSnapshot == INVALID_HANDLE_VALUE)
        return NULL;

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
    const DWORD dwDestProcId = DbgUtility::getProcessIdFromeName(process_name);
    HANDLE  hTempWnd = FindWindow(NULL, NULL);
    DWORD   dwTempProcId = 0;

    while (hTempWnd != NULL)
    {
        GetWindowThreadProcessId(static_cast<HWND>(hTempWnd), &dwTempProcId);
        if (dwDestProcId == dwTempProcId)
        {
            return hTempWnd;
        }
        hTempWnd = GetWindow(static_cast<HWND>(hTempWnd), GW_HWNDNEXT);
    }

    return NULL;
}

void DbgUtility::dbgPrint(const char *format, ...)
{
    va_list arg_list;
    char tmp[1024] = { 0, };
    va_start(arg_list, format);
    vsprintf_s(tmp, sizeof(tmp), format, arg_list);
    va_end(arg_list);

    OutputDebugString(tmp);
}

void DbgUtility::dbgPrint(const wchar_t *format, ...)
{
    va_list arg_list;
    wchar_t tmp[1024] = { 0, };
    va_start(arg_list, format);
    vswprintf_s(tmp, sizeof(tmp) / sizeof(wchar_t), format, arg_list);

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

UINT DbgUtility::setBreakpoints()
{
    BYTE byte;
    originalOpInfo opInfo;
    FILE *fp;
    fopen_s(&fp, m_targetFileName.c_str(), "rb");
    
    // 0xE8
    while ((byte = fgetc(fp)) != EOF)
    {
        if (CALL_1 == byte)
        {
            opInfo.chOpcode = byte;
            DWORD raw = (ftell(fp) - 1) - ;
            opInfo.dwAddress = 
        }
    }

    // 0xFF15
}