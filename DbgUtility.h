#pragma once

#include <Windows.h>
#include <string>

class DbgUtility
{
public:
    DbgUtility(std::string process_name = "");
    ~DbgUtility();

    bool doDebuggerProc();

    std::string GetTargetFileName();
    HANDLE GetWindowsHandle();

    void setTargetFileName(const char *file_name);
    void setTargetFileName(std::string& file_name);

    static void dbgPrint(const char *format, ...);
    static void dbgPrint(const wchar_t *format, ...);
    static DWORD getProcessIdFromeName(std::string& process_name);
    static HANDLE getWindowsHandleFromeName(std::string& process_name);
    static bool checkRemoteDbgPresent(HANDLE hProc);
    static bool doDebuggerProc(std::string& file_name, PROCESS_INFORMATION& process_info, STARTUPINFO& startup_info_);
    static std::string getFileNameFromeHandle(HANDLE hFile);
private:
    std::string m_targetFileName;
    PROCESS_INFORMATION m_procInfo;
    STARTUPINFO m_startInfo;
};