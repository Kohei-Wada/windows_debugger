int get_index_of_bp(LPVOID addr);
int bp_set(LPVOID addr);
void dump_context(CONTEXT *context);
FARPROC func_resolver(LPCSTR dll, LPCSTR func);

DWORD event_handler_exception(DEBUG_EVENT *dbg);
DWORD event_handler_create_thread(DEBUG_EVENT *dbg);
DWORD event_handler_create_process(DEBUG_EVENT *dbg);
DWORD event_handler_exit_thread(DEBUG_EVENT *dbg);
DWORD event_handler_load_dll(DEBUG_EVENT *dbg);
DWORD event_handler_unload_dll(DEBUG_EVENT *dbg);
DWORD event_handler_output_debug_string(DEBUG_EVENT *dbg);
DWORD event_handler_rip_event(DEBUG_EVENT *dbg);
DWORD event_handler_exit_process(DEBUG_EVENT *dbg);
