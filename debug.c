#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <Windows.h>

#include "handler.h"




int      debugger_active = 1;
DWORD    pid;
HANDLE   h_process;
HANDLE   h_thread;
CONTEXT  context;




int _log(char *fmt, ...)
{
int log = 1;

    if(log){
        va_list args;

        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
    }

    return 0;
}



int _err(char *msg)
{
int err = 1;
    if(err){
        fprintf(stderr, "error: %s erno = %ld\n", msg, GetLastError());
    }
    return 0;
}




int get_debug_privileges()
{
HANDLE            h_token;
LUID              luid;
TOKEN_PRIVILEGES  token_state;

    if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &h_token) == 0){
        _err("OpenProcessToken");
        return 1;
    }
    if(LookupPrivilegeValueA(0, "SeDebugPrivilege", &luid) == 0){
        _err("LookupPrivilegeValueA");
        CloseHandle(h_token);
        return 1;
    }
    token_state.PrivilegeCount = 1;
    token_state.Privileges[0].Luid = luid;
    token_state.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if(AdjustTokenPrivileges(h_token, 0, &token_state, 0, 0, 0) == 0){
        _err("AdjustTokenPrivileges");
        CloseHandle(h_token);
        return 1;
    }

    return 0;

}




int get_debug_event(void)
{
DEBUG_EVENT   dbg;
DWORD         continue_status = DBG_CONTINUE;


    if(WaitForDebugEvent(&dbg, INFINITE) == 0)
        return 1;

    h_thread = OpenThread(THREAD_ALL_ACCESS, 0, dbg.dwThreadId);

    context.ContextFlags = CONTEXT_FULL;
    if(GetThreadContext(h_thread, &context) == 0){
        _err("GetThreadContext");
        return 1;
    }

    //printf("ExceptionCode = %ld  Thread ID = %ld\n", dbg.dwDebugEventCode, dbg.dwThreadId);
    switch(dbg.dwDebugEventCode){

        case EXCEPTION_DEBUG_EVENT:
            continue_status = event_handler_exception(&dbg);
            break;

        case CREATE_THREAD_DEBUG_EVENT:
            continue_status = event_handler_create_thread(&dbg);
            break;

        case CREATE_PROCESS_DEBUG_EVENT:
            continue_status = event_handler_create_process(&dbg);
            break;

        case EXIT_THREAD_DEBUG_EVENT:
            continue_status = event_handler_exit_thread(&dbg);
            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            continue_status = event_handler_exit_process(&dbg);
            break;

        case LOAD_DLL_DEBUG_EVENT:
            continue_status = event_handler_load_dll(&dbg);
            break;

        case UNLOAD_DLL_DEBUG_EVENT:
            continue_status = event_handler_unload_dll(&dbg);
            break;

        case OUTPUT_DEBUG_STRING_EVENT:
            continue_status = event_handler_output_debug_string(&dbg);
            break;

        case RIP_EVENT:
            continue_status = event_handler_rip_event(&dbg);
            break;

        default :  break;
    }

    CloseHandle(h_thread);
    FlushInstructionCache(h_process, 0, 0);
    ContinueDebugEvent(dbg.dwProcessId, dbg.dwThreadId, continue_status);
    return 0;
}




int main(int argc, char **argv)
{

    if(argc < 2){
        fprintf(stderr, "Usage: [pid]");
        return 1;
    }


    pid = atoi(argv[1]);

    get_debug_privileges();

    if((h_process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid)) == 0){
        _err("openprocess");
        return 1;
    }


    LPCSTR func = "printf";
    LPCSTR dll = "Msvcrt.dll";
    FARPROC bp_addr = func_resolver(dll, func);
    _log("[L O G] func-addr = %p\n", bp_addr);
    bp_set(bp_addr);



    DebugActiveProcess(pid);
    _log("[L O G] attach to pid: %ld\n", pid);

    while(debugger_active){
        if(get_debug_event() == 1)
            break;
    }
    DebugActiveProcessStop(pid);
    _log("[L O G] Detach from target process...\n");

    return 0;
}
