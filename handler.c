#include <Windows.h>
#include <stdio.h>

#include "breakpoint.h"
#define MAX_SIZE 256


extern int _log(char *fmt, ...);
extern int _err(char *msg);

extern int        debugger_active;
extern DWORD      pid;
extern HANDLE     h_process;
extern HANDLE     h_thread;
extern CONTEXT    context;


struct BREAKPOINT breakpoint[MAX_SIZE];
int num_of_bps = 0;
int restore_bp_index = -1;



int get_index_of_bp(LPVOID addr)
{
    for(int index = 0; index < num_of_bps; ++index){
        if(addr == breakpoint[index].addr)
            return index;
    }
    return -1;
}



void dump_context(CONTEXT *context){
    printf("-----------------context-----------------\n");
    printf(" [rip] %I64d\n", context -> Rip);
    printf(" [rcx] %I64d\n", context -> Rcx);
    printf(" [rdx] %I64d\n", context -> Rdx);
    printf(" [r 8] %I64d\n", context -> R8);
    printf(" [r 9] %I64d\n", context -> R9);
    printf(" [rdi] %I64d\n", context -> Rdi);
    printf(" [rsi] %I64d\n", context -> Rsi);
    printf(" [rax] %I64d\n", context -> Rax);
    printf("-----------------------------------------\n");
}



int bp_set(LPVOID addr)
{
int set_index;

    if((set_index = get_index_of_bp(addr)) == -1){
        printf("[L O G] new bp set\n");
        set_index = num_of_bps;
        ++num_of_bps;

    }
    if(!ReadProcessMemory(h_process, addr, breakpoint[set_index].original_byte, 1, NULL)){
        _err("ReadProcessMemory");
        return 1;
    }
    if(!WriteProcessMemory(h_process, addr, "\xCC", 1, NULL)){
        _err("WriteProcessMemory");
        return 1;
    }

    _log("[L O G] breakpoint set at %p\n", addr);
    breakpoint[set_index].addr = addr;
    breakpoint[set_index].set_again = 1;

    return 0;
}




FARPROC func_resolver(LPCSTR dll, LPCSTR func)
{
HANDLE   handle;
LPCVOID  address;

    if((handle = LoadLibraryA(dll)) == 0){
        _err("LoadLibraryA");
        return NULL;
    }
    if((address = GetProcAddress(handle, func)) == 0){
        _err("GetProcAddress");
        return NULL;
    }
    FreeLibrary(handle);
    return address;
}





DWORD exception_handler_breakpoint(EXCEPTION_DEBUG_INFO *info)
{
static int first_break_hit = 0;

LPVOID exception_addr = info -> ExceptionRecord.ExceptionAddress;
int index_of_bp;


    if((index_of_bp = get_index_of_bp(exception_addr)) >= 0){
        restore_bp_index = index_of_bp;

        dump_context(&context);

        _log("    our breakpoint\n");
        _log("    restoring original byte\n");

        WriteProcessMemory(h_process, breakpoint[index_of_bp].addr, breakpoint[index_of_bp].original_byte, 1, NULL);

        context.Rip -= 1;
        context.EFlags = 256;

        if(SetThreadContext(h_thread, &context) == 0){
            _err("SetThreadContext");
        }

    }
    else{
        if(first_break_hit){
            _log("    unknown breakpoint detected\n");
        }

        else{
            _log("    First windows breakpoint.\n");
            first_break_hit = 1;
        }
    }
    
    return DBG_CONTINUE;
}




DWORD exception_handler_single_step(EXCEPTION_DEBUG_INFO *info)
{
    dump_context(&context);

    if(restore_bp_index >= 0){
        _log("set again breakpoint\n");
        if(breakpoint[restore_bp_index].set_again){
            bp_set(breakpoint[restore_bp_index].addr);
        }
    }

    restore_bp_index = -1;
    return DBG_CONTINUE;
}





DWORD event_handler_exception(DEBUG_EVENT *dbg)
{
DWORD   continue_status = DBG_CONTINUE;
EXCEPTION_DEBUG_INFO info = dbg -> u.Exception;
    _log("[EVENT] Exception at0x %p\n", info.ExceptionRecord.ExceptionAddress);

    //printf("Exception at %p   first-chance = %ld\n",
    //info.ExceptionRecord.ExceptionAddress, info.dwFirstChance);

    switch(info.ExceptionRecord.ExceptionCode){
        case EXCEPTION_ACCESS_VIOLATION:
            _log("    [!] Access violation.\n");
            continue_status = DBG_EXCEPTION_NOT_HANDLED;
            break;

        case EXCEPTION_BREAKPOINT:
            _log("    [*] Breakpoint.\n");
            continue_status = exception_handler_breakpoint(&info);
            break;

        case EXCEPTION_GUARD_PAGE:
            _log("    [!] Guard page.\n");
            continue_status = DBG_EXCEPTION_NOT_HANDLED;
            break;

        case EXCEPTION_SINGLE_STEP:
            _log("    [*] Single step.\n");
            continue_status = exception_handler_single_step(&info);
            break;

        default:
            _log("    [!] not handled exception\n");
            continue_status = DBG_EXCEPTION_NOT_HANDLED;
            break;
    }

    return continue_status;

}




DWORD event_handler_create_thread(DEBUG_EVENT *dbg)
{
CREATE_THREAD_DEBUG_INFO info = dbg->u.CreateThread;

    _log("[EVENT] Thread (handle: 0x%p  id: %ld) created at: 0x%p\n", info.hThread, dbg->dwThreadId, info.lpStartAddress);

    return DBG_CONTINUE;
}



DWORD event_handler_create_process(DEBUG_EVENT *dbg)
{
CREATE_PROCESS_DEBUG_INFO info = dbg->u.CreateProcessInfo;

    _log("[EVENT] Create Process: at 0x%p\n", info.lpStartAddress);
    return DBG_CONTINUE;
}



DWORD event_handler_exit_thread(DEBUG_EVENT *dbg)
{
EXIT_THREAD_DEBUG_INFO info = dbg->u.ExitThread;
    _log("[EVENT] Thread %ld exited with code: %ld\n", dbg->dwThreadId, info.dwExitCode);
    return DBG_CONTINUE;
}



DWORD event_handler_exit_process(DEBUG_EVENT *dbg)
{
EXIT_PROCESS_DEBUG_INFO info = dbg-> u.ExitProcess;
    _log("[EVENT] Process exited with code: 0x%lx\n", info.dwExitCode);
    debugger_active = 0;
    return DBG_CONTINUE;
}



DWORD event_handler_load_dll(DEBUG_EVENT *dbg)
{
LOAD_DLL_DEBUG_INFO info = dbg-> u.LoadDll;

    _log("[EVENT] Load DLL: at 0x%p\n", info.lpBaseOfDll);
    return DBG_CONTINUE;
}



DWORD event_handler_unload_dll(DEBUG_EVENT *dbg)
{
//UNLOAD_DLL_DEBUG_INFO info = dbg->u.UnloadDll;
    _log("[EVENT] Unload DLL:\n");
    return DBG_CONTINUE;
}



DWORD event_handler_output_debug_string(DEBUG_EVENT *dbg)
{
OUTPUT_DEBUG_STRING_INFO  info = dbg->u.DebugString;
WCHAR msg[info.nDebugStringLength];

    ReadProcessMemory(h_process, info.lpDebugStringData, msg, info.nDebugStringLength, NULL);
    _log("[EVENT] Output string.\n");
    //printf("Output String: %hs\n", msg);
    return DBG_CONTINUE;
}



DWORD event_handler_rip_event(DEBUG_EVENT *dbg)
{
//RIP_INFO info = dbg ->u.RipInfo;
    _log("[EVENT] Rip event\n");
    return DBG_CONTINUE;
}
