# Original project at https://github.com/psychomario/pyinject
# The project is licensed under the terms of the MIT license; see
# accompanying LICENSE.md for details.

import ctypes
import ctypes.wintypes as wintypes
import platform
import binascii
import os

wintypes.LPTSTR = ctypes.POINTER(ctypes.c_char)
wintypes.LPBYTE = ctypes.POINTER(ctypes.c_ubyte)
wintypes.HANDLE = ctypes.c_void_p
wintypes.LPDWORD = ctypes.POINTER(wintypes.DWORD)
wintypes.LPCTSTR = ctypes.POINTER(ctypes.c_char)
wintypes.PHANDLE = ctypes.POINTER(wintypes.HANDLE)

class __LUID(ctypes.Structure):
    """see: 
http://msdn.microsoft.com/en-us/library/windows/desktop/aa379261(v=vs.85).aspx
"""
    _fields_ = [("LowPart", wintypes.DWORD),
              ("HighPart", wintypes.LONG),]
wintypes.LUID = __LUID
wintypes.PLUID = wintypes.POINTER(wintypes.LUID)
class __LUID_AND_ATTRIBUTES(ctypes.Structure):
    """see: 
http://msdn.microsoft.com/en-us/library/windows/desktop/aa379263(v=vs.85).aspx
"""
    _fields_ = [("Luid",        wintypes.LUID),
        ("Attributes",  wintypes.DWORD),]
wintypes.LUID_AND_ATTRIBUTES = __LUID_AND_ATTRIBUTES
wintypes.PLUID_AND_ATTRIBUTES = wintypes.POINTER(wintypes.LUID_AND_ATTRIBUTES)
class __TOKEN_PRIVILEGES(ctypes.Structure):
    """see: 
http://msdn.microsoft.com/en-us/library/windows/desktop/aa379630(v=vs.85).aspx
"""
    _fields_ = [("PrivilegeCount",  wintypes.DWORD),
        ("Privileges",      wintypes.LUID_AND_ATTRIBUTES),]
wintypes.TOKEN_PRIVILEGES = __TOKEN_PRIVILEGES
wintypes.PTOKEN_PRIVILEGES = wintypes.POINTER(wintypes.TOKEN_PRIVILEGES)
class __STARTUPINFO(ctypes.Structure):
    """see: 
http://msdn.microsoft.com/en-us/library/windows/desktop/ms686331(v=vs.85).aspx
"""
    _fields_ = [("cb",            wintypes.DWORD),        
                ("lpReserved",    wintypes.LPTSTR), 
                ("lpDesktop",     wintypes.LPTSTR),  
                ("lpTitle",       wintypes.LPTSTR),
                ("dwX",           wintypes.DWORD),
                ("dwY",           wintypes.DWORD),
                ("dwXSize",       wintypes.DWORD),
                ("dwYSize",       wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute",wintypes.DWORD),
                ("dwFlags",       wintypes.DWORD),
                ("wShowWindow",   wintypes.WORD),
                ("cbReserved2",   wintypes.WORD),
                ("lpReserved2",   wintypes.LPBYTE),
                ("hStdInput",     wintypes.HANDLE),
                ("hStdOutput",    wintypes.HANDLE),
                ("hStdError",     wintypes.HANDLE),]
wintypes.STARTUPINFO = __STARTUPINFO
wintypes.LPSTARTUPINFO = wintypes.POINTER(wintypes.STARTUPINFO)
class __PROCESS_INFORMATION(ctypes.Structure):
    """see: 
http://msdn.microsoft.com/en-us/library/windows/desktop/ms684873(v=vs.85).aspx
"""
    _fields_ = [("hProcess",    wintypes.HANDLE),
                ("hThread",     wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD),
                ("dwThreadId",  wintypes.DWORD),]
wintypes.PROCESS_INFORMATION = __PROCESS_INFORMATION
wintypes.LPPROCESS_INFORMATION = wintypes.POINTER(wintypes.PROCESS_INFORMATION)
class __SYSTEM_MODULE_INFORMATION(ctypes.Structure):
	_fields_ = [("ModuleCount",		wintypes.ULONG),
		("WhoCares",		ctypes.c_void_p * 2),
		("BaseAddress",		ctypes.c_void_p),
		("Size",		wintypes.ULONG),
		("MoarStuff",		wintypes.ULONG),
		("MoarMoar",		wintypes.USHORT),
		("HeyThere",		wintypes.USHORT),
		("Pwned",		wintypes.USHORT),
		("W00t",		wintypes.USHORT),
		("ImageName",		ctypes.c_char * 256),]
wintypes.SYSTEM_MODULE_INFORMATION = __SYSTEM_MODULE_INFORMATION
wintypes.PSYSTEM_MODULE_INFORMATION = wintypes.POINTER(wintypes.SYSTEM_MODULE_INFORMATION)
class __IMAGE_DOS_HEADER(ctypes.Structure):
        _fields_ = [("e_magic",    wintypes.WORD),
                    ("e_cblp",     wintypes.WORD),
                    ("e_cp",       wintypes.WORD),
                    ("e_crlc",     wintypes.WORD),
                    ("e_cparhdr",  wintypes.WORD),
                    ("e_minalloc", wintypes.WORD),
                    ("e_maxalloc", wintypes.WORD),
                    ("e_ss",       wintypes.WORD),
                    ("e_sp",       wintypes.WORD),
                    ("e_csum",     wintypes.WORD),
                    ("e_ip",       wintypes.WORD),
                    ("e_cs",       wintypes.WORD),
                    ("e_lfarlc",   wintypes.WORD),
                    ("e_ovno",     wintypes.WORD),
                    ("e_res",      wintypes.WORD * 4),
                    ("e_oemid",    wintypes.WORD),
                    ("e_oeminfo",  wintypes.WORD),
                    ("e_res2",     wintypes.WORD * 10),
                    ("e_lfanew",   wintypes.LONG),]
wintypes.IMAGE_DOS_HEADER = __IMAGE_DOS_HEADER
wintypes.PIMAGES_DOS_HEADER = wintypes.POINTER(wintypes.IMAGE_DOS_HEADER)
class __IMAGE_FILE_HEADER(ctypes.Structure):
        _fields_ = [("Machine",              wintypes.WORD),
                    ("NumberOfSections",     wintypes.WORD),
                    ("TimeDateStamp",        wintypes.DWORD),
                    ("PointerToSymbolTable", wintypes.DWORD),
                    ("NumberOfSymbols",      wintypes.DWORD),
                    ("SizeOfOptionalHeader", wintypes.WORD),
                    ("Characteristics",      wintypes.WORD),]
wintypes.IMAGE_FILE_HEADER = __IMAGE_FILE_HEADER
wintypes.PIMAGE_FILE_HEADER = wintypes.POINTER(wintypes.IMAGE_FILE_HEADER)
class __IMAGE_DATA_DIRECTORY(ctypes.Structure):
        _fields_ = [("VirtualAddress", wintypes.DWORD),
                    ("Size",           wintypes.DWORD),]
wintypes.IMAGE_DATA_DIRECTORY = __IMAGE_DATA_DIRECTORY
wintypes.PIMAGE_DATA_DIRECTORY = wintypes.POINTER(wintypes.IMAGE_DATA_DIRECTORY)
class __IMAGE_OPTIONAL_HEADER(ctypes.Structure):
        _fields_ = [("Magic",                        wintypes.WORD),
                    ("MajorLinkerVersion",           wintypes.BYTE),
                    ("MinorLinkerVersion",           wintypes.BYTE),
                    ("SizeOfCode",                   wintypes.DWORD),
                    ("SizeOfInitializedData",        wintypes.DWORD),
                    ("SizeOfUninitializedData",      wintypes.DWORD),
                    ("AddressOfEntryPoint",          wintypes.DWORD),
                    ("BaseOfCode",                   wintypes.DWORD),
                    ("BaseOfData",                   wintypes.DWORD),
                    ("ImageBase",                    wintypes.DWORD),
                    ("SectionAlignment",             wintypes.DWORD),
                    ("FileAlignment",                wintypes.DWORD),
                    ("MajorOperatingSystemVersion",  wintypes.WORD),
                    ("MinorOperatingSystemVersion",  wintypes.WORD),
                    ("MajorImageVersion",            wintypes.WORD),
                    ("MinorImageVersion",            wintypes.WORD),
                    ("MajorSubsystemVersion",        wintypes.WORD),
                    ("MinorSubsystemVersion",        wintypes.WORD),
                    ("Win32VersionValue",            wintypes.DWORD),
                    ("SizeOfImage",                  wintypes.DWORD),
                    ("SizeOfHeaders",                wintypes.DWORD),
                    ("CheckSum",                     wintypes.DWORD),
                    ("Subsystem",                    wintypes.WORD),
                    ("DllCharacteristics",           wintypes.WORD),
                    ("SizeOfStackReserve",           wintypes.DWORD),
                    ("SizeOfStackCommit",            wintypes.DWORD),
                    ("SizeOfHeapReserve",            wintypes.DWORD),
                    ("SizeOfHeapCommit",             wintypes.DWORD),
                    ("LoaderFlags",                  wintypes.DWORD),
                    ("NumberOfRvaAndSizes",          wintypes.DWORD),
                    ("DataDirectory",                wintypes.IMAGE_DATA_DIRECTORY * 16),]
wintypes.IMAGE_OPTIONAL_HEADER = __IMAGE_OPTIONAL_HEADER
wintypes.PIMAGE_OPTIONAL_HEADER = wintypes.POINTER(wintypes.IMAGE_OPTIONAL_HEADER)
class __IMAGE_NT_HEADER(ctypes.Structure):
        _fields_ = [("Signature", wintypes.DWORD),
                    ("FileHeader", wintypes.IMAGE_FILE_HEADER),
                    ("OptionalHeader", wintypes.IMAGE_OPTIONAL_HEADER),]
wintypes.IMAGE_NT_HEADER = __IMAGE_NT_HEADER
wintypes.PIMAGE_NT_HEADER = wintypes.POINTER(wintypes.IMAGE_NT_HEADER)
class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength",                         wintypes.DWORD),
                ("lpSecurityDescriptor",            wintypes.LPVOID),
                ("bInheritHandle",                  wintypes.BOOL)]
LPSECURITY_ATTRIBUTES = wintypes.POINTER(SECURITY_ATTRIBUTES)
wintypes.LPTHREAD_START_ROUTINE = wintypes.LPVOID

class Process():
    """This class can be used for dll or shellcode injection.
Process(pid=pid)
This will attach to process with pid=pid assuming
you have proper privileges

Process(pe=path)
Starts the executable at path

self.inject(dllpath)
Injects dll at dllpath

self.injectshellcode(shellcode)
Injects raw shellcode in the string shellcode

self.terminate(code)
This will terminate the process in use regardless of where it was
started from. code is the exit code"""
    def __init__(self, pid=None, pe=None, handle=None):
        self.kernel32 = ctypes.windll.kernel32
        self.PROCESS_ALL_ACCESS = (0x000F0000L|0x00100000L|0xFFF)
        self.SE_DEBUG_NAME = "SeDebugPrivilege"
        self.TOKEN_ADJUST_PRIVILEGES = 0x20
        self.SE_PRIVILEGE_ENABLED = 0x00000002
        self.request_debug_privileges()
 
        if pid: #attach to current file
            self.kernel32.OpenProcess.restype = wintypes.HANDLE
            self.kernel32.OpenProcess.argtypes = [ wintypes.DWORD,
                                                   wintypes.BOOL,
                                                   wintypes.DWORD ]

            result = self.handle = self.kernel32.OpenProcess(
                                                    self.PROCESS_ALL_ACCESS,
                                                    False,
                                                    pid
                                                    )
            self.get_last_error("OpenProcess", result)
            self.pid = pid
        elif pe: #create new process
            startupinfo = wintypes.STARTUPINFO()
            process_information = wintypes.PROCESS_INFORMATION()
            startupinfo.dwFlags = 0x1
            startupinfo.wShowWindow = 0x0
            startupinfo.cb = ctypes.sizeof(startupinfo)
            self.kernel32.CreateProcessA.restype = wintypes.BOOL
            self.kernel32.CreateProcessA.argtypes = [ wintypes.LPCSTR,
                                                      wintypes.LPTSTR,
                                                      LPSECURITY_ATTRIBUTES,
                                                      LPSECURITY_ATTRIBUTES,
                                                      wintypes.BOOL,
                                                      wintypes.DWORD,
                                                      wintypes.LPVOID,
                                                      wintypes.LPCTSTR,
                                                      wintypes.LPSTARTUPINFO,
                                                      wintypes.LPPROCESS_INFORMATION ]
            result = self.kernel32.CreateProcessA(
                                        pe,
                                        None,
                                        None,
                                        None,
                                        True,
                                        0,
                                        None,
                                        None,
                                        ctypes.byref(startupinfo),
                                        ctypes.byref(process_information)
                                        )
            self.get_last_error("CreateProcessA", result)
            if result == 0 :
                print "CreateProcessA Failed!"
                return None
            self.handle = process_information.hProcess
            self.pid = process_information.dwProcessId
        elif handle:
            self.handle = handle
            self.pid = None
        else:
            return None
                  
        self.arch = platform.architecture()[0][:2]
        if self.arch == 32:
            self.addrlen = 4
        else:
            self.addrlen = 8

    def get_last_error(self, desc, val):
        return # Comment out the return to see return and error values
        print "%s=0x%x, GetCurrentError=0x%x (%d)" % (desc, val, self.kernel32.GetLastError(), self.kernel32.GetLastError())

    def request_debug_privileges(self):
        """Adds SeDebugPrivilege to current process for various needs"""
        privs = wintypes.LUID()
        ctypes.windll.advapi32.LookupPrivilegeValueA.restype = wintypes.BOOL
        ctypes.windll.advapi32.LookupPrivilegeValueA.argtypes = [ wintypes.LPCTSTR,
                                                                  wintypes.LPCTSTR,
                                                                  wintypes.PLUID ]
        result = ctypes.windll.advapi32.LookupPrivilegeValueA(
                                                    None,
                                                    self.SE_DEBUG_NAME,
                                                    ctypes.byref(privs)
                                                    )
        self.get_last_error("LookupPrivilegeValueA",result)
        token = wintypes.TOKEN_PRIVILEGES(
                                            1,
                                            wintypes.LUID_AND_ATTRIBUTES(
                                                                        privs,
                                                                        self.SE_PRIVILEGE_ENABLED
                                                                        )
                                            )
        hToken = wintypes.HANDLE()
        ctypes.windll.advapi32.OpenProcessToken.restype = wintypes.BOOL
        ctypes.windll.advapi32.OpenProcessToken.argtypes = [ wintypes.HANDLE,
                                                             wintypes.DWORD,
                                                             wintypes.PHANDLE ]
        result = ctypes.windll.advapi32.OpenProcessToken(
                                                wintypes.HANDLE(self.kernel32.GetCurrentProcess()),
                                                self.TOKEN_ADJUST_PRIVILEGES,
                                                ctypes.byref(hToken)
                                                )
        self.get_last_error("OpenProcessToken",result)
        ctypes.windll.advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL
        ctypes.windll.advapi32.AdjustTokenPrivileges.argtypes = [ wintypes.HANDLE,
                                                                  wintypes.BOOL,
                                                                  wintypes.PTOKEN_PRIVILEGES,
                                                                  wintypes.DWORD,
                                                                  wintypes.PTOKEN_PRIVILEGES,
                                                                  wintypes.LPDWORD ]
        result = ctypes.windll.advapi32.AdjustTokenPrivileges(
                                                    hToken,
                                                    False,
                                                    ctypes.byref(token),
                                                    0x0,
                                                    None,
                                                    None
                                                    )
        self.get_last_error("AdjustTokenPrivileges",result)

        ctypes.windll.kernel32.CloseHandle.restype = wintypes.BOOL
        ctypes.windll.kernel32.CloseHandle.argtypes = [ wintypes.HANDLE ]
        result = ctypes.windll.kernel32.CloseHandle(hToken)
        self.get_last_error("CloseHandle", result)

    def inject(self,dllpath):
        """This function injects dlls the smart way
specifying stack rather than pushing and calling"""
        dllpath = os.path.abspath(dllpath)

        self.kernel32.GetModuleHandleA.restype = wintypes.HANDLE
        self.kernel32.GetModuleHandleA.argtypes = [ wintypes.LPCTSTR ]
        ModuleHandle = self.kernel32.GetModuleHandleA("kernel32.dll")
        self.get_last_error("GetModuleHandle",ModuleHandle)

        self.kernel32.GetProcAddress.restype = wintypes.LPVOID
        self.kernel32.GetProcAddress.argtypes = [ wintypes.HANDLE, wintypes.LPCSTR ]
        LoadLibraryA = self.kernel32.GetProcAddress(
                            wintypes.HANDLE(ModuleHandle),
                            "LoadLibraryA")
        self.get_last_error("GetProcAddress", LoadLibraryA);

        self.kernel32.VirtualAllocEx.restype = wintypes.LPVOID
        self.kernel32.VirtualAllocEx.argtypes = [ wintypes.HANDLE,
                                                  wintypes.LPVOID,
                                                  ctypes.c_size_t,
                                                  wintypes.DWORD,
                                                  wintypes.DWORD ]
        RemotePage = self.kernel32.VirtualAllocEx(
                                                self.handle,
                                                None,
                                                len(dllpath)+1,
                                                0x1000, # MEM_COMMIT
                                                0x40 # PAGE_EXECUTE_READWRITE
                                                )
        self.get_last_error("VirtualAllocEx", RemotePage)

        self.kernel32.WriteProcessMemory.restype = wintypes.BOOL
        self.kernel32.WriteProcessMemory.argtypes = [ wintypes.HANDLE,
                                                      wintypes.LPVOID,
                                                      wintypes.LPCVOID,
                                                      ctypes.c_size_t,
                                                      ctypes.POINTER(ctypes.c_size_t) ]
        result = self.kernel32.WriteProcessMemory(
                                        self.handle,
                                        RemotePage,
                                        dllpath,
                                        len(dllpath),
                                        None
                                        )
        self.get_last_error("WriteProcessMemory",result)

        self.kernel32.CreateRemoteThread.restype = wintypes.HANDLE
        self.kernel32.CreateRemoteThread.argtypes = [ wintypes.HANDLE,
                                                      LPSECURITY_ATTRIBUTES,
                                                      ctypes.c_size_t,
                                                      wintypes.LPTHREAD_START_ROUTINE,
                                                      wintypes.LPVOID,
                                                      wintypes.DWORD,
                                                      wintypes.LPVOID ]
        RemoteThread = self.kernel32.CreateRemoteThread(
                                                        self.handle,
                                                        None,
                                                        0,
                                                        LoadLibraryA,
                                                        RemotePage,
                                                        0,
                                                        None
                                                        )
        self.get_last_error("CreateRemoteThread",RemoteThread)

        self.kernel32.WaitForSingleObject.restype = wintypes.DWORD
        self.kernel32.WaitForSingleObject.argtypes = [ wintypes.HANDLE, wintypes.DWORD ]
        # Wait 10 seconds then barrel on...
        result = self.kernel32.WaitForSingleObject(
                                        RemoteThread,
                                        10*1000 # 10 seconds.  -1 for infinite
                                        )
        self.get_last_error("WaitForSingleObject",result)

        exitcode = wintypes.DWORD(0)
        self.kernel32.GetExitCodeThread.restype = wintypes.BOOL
        self.kernel32.GetExitCodeThread.argtypes = [ wintypes.HANDLE, wintypes.LPDWORD ]
        result = self.kernel32.GetExitCodeThread(
                                        RemoteThread,
                                        ctypes.byref(exitcode)
                                        )
        self.get_last_error("GetExitCodeThread",result)
        # print "exitcode = %s" % str(exitcode)

        self.kernel32.VirtualFreeEx.restype = wintypes.BOOL
        self.kernel32.VirtualFreeEx.argtypes = [ wintypes.HANDLE,
                                                 wintypes.LPVOID,
                                                 ctypes.c_size_t,
                                                 wintypes.DWORD ]
        result = self.kernel32.VirtualFreeEx(
                                    self.handle,
                                    RemotePage,
                                    0, # Size.  Must be 0 for MEM_RELEASE
                                    0x8000 # MEM_RELEASE
                                    )
        self.get_last_error("VirtualFreeEx",result)
        return exitcode.value

    def injectshellcode(self, shellcode):
        """This function merely executes what it is given"""
        self.kernel32.VirtualAllocEx.restype = wintypes.LPVOID
        self.kernel32.VirtualAllocEx.argtypes = [ wintypes.HANDLE,
                                                  wintypes.LPVOID,
                                                  ctypes.c_size_t,
                                                  wintypes.DWORD,
                                                  wintypes.DWORD ]
        shellcodeaddress = self.kernel32.VirtualAllocEx(
                                                        self.handle,
                                                        None,
                                                        len(shellcode),
                                                        0x1000, # MEM_COMMIT
                                                        0x40 # PAGE_EXECUTE_READWRITE
                                                        )
        self.get_last_error("VirtualAllocEx", shellcodeaddress)

        self.kernel32.WriteProcessMemory.restype = wintypes.BOOL
        self.kernel32.WriteProcessMemory.argtypes = [ wintypes.HANDLE,
                                                      wintypes.LPVOID,
                                                      wintypes.LPCVOID,
                                                      ctypes.c_size_t,
                                                      ctypes.POINTER(ctypes.c_size_t) ]
        result = self.kernel32.WriteProcessMemory(
                                        self.handle,
                                        shellcodeaddress,
                                        shellcode,
                                        len(shellcode),
                                        None
                                        )
        self.get_last_error("WriteProcessMemory", result);

        self.kernel32.CreateRemoteThread.restype = wintypes.HANDLE
        self.kernel32.CreateRemoteThread.argtypes = [ wintypes.HANDLE,
                                                      LPSECURITY_ATTRIBUTES,
                                                      ctypes.c_size_t,
                                                      wintypes.LPTHREAD_START_ROUTINE,
                                                      wintypes.LPVOID,
                                                      wintypes.DWORD,
                                                      wintypes.LPVOID ]
        thread = self.kernel32.CreateRemoteThread(
                                        self.handle,
                                        None,
                                        0,
                                        shellcodeaddress,
                                        None,
                                        0,
                                        None
                                        )
        self.get_last_error("CreateRemoteThread", thread);

    def injectshellcodefromfile(self, file, bzipd=False):
        """This function merely executes what it is given as a raw file"""
        fh=open(file,'rb')
        shellcode=fh.read()
        fh.close()
        if bzipd:
            import bz2
            shellcode=bz2.decompress(shellcode)
        self.injectshellcode(shellcode)

    def terminate(self, code=0):
        """This function terminates the process from the current handle"""
        self.kernel32.TerminateProcess.restype = wintypes.BOOL
        self.kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        result = self.kernel32.TerminateProcess(
                                        self.handle,
                                        code
                                        )
        self.get_last_error("TerminateProcess",result)
        self.kernel32.CloseHandle(self.handle)
