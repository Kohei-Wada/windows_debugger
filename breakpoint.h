
struct BREAKPOINT{
    LPCSTR    func;
    LPVOID    addr;
    WCHAR     original_byte[1];
    int       set_again;
};
