#pragma once

#include <Windows.h>
#include <functional>
#include <string>
#include "PEparser.h"

class DbgUtility
{
public:
    virtual void onExcuteOnceInstruction(DEBUG_EVENT& _event);
    virtual void onCreateProcess(DEBUG_EVENT& _event);
    virtual void onExitProcess(DEBUG_EVENT& _event);

    DbgUtility(std::string process_name = "");
    ~DbgUtility();

    bool start();
    void stop();
    void resume();

    std::string GetTargetFileName();
    HANDLE GetWindowsHandle();
    void setFilePath(const char *file_name);
    void setFilePath(std::string& file_name);
    void setTrapFlag(bool _enable);
    CONTEXT getCurrentDebuggeeContext();
    PROCESS_INFORMATION getDebuggeeProcInfo();

    static void dbgPrint(const char *format, ...);
    static void dbgPrint(const wchar_t *format, ...);
    static DWORD getProcessIdFromName(std::string& process_name);
    static HANDLE getWindowsHandleFromName(std::string& process_name);
    static bool checkRemoteDbgPresent(HANDLE hProc);
    static std::string getFileNameFromHandle(HANDLE hFile);

private:
    bool m_trapFlag;
    bool m_stop;
    bool m_resume;

    std::string m_filePath;
    STARTUPINFO m_startInfo;
    
    LPVOID m_oep;
    HANDLE m_module;
    BYTE m_breakPoint, m_INT3;

protected:
    CONTEXT dbgContext;
    PROCESS_INFORMATION dbgProcInfo;
    PEparser dbgPEInfo;
};