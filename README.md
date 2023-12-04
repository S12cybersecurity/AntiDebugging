# AntiDebugging
Anti Debugging C++ Class

# Techniques Covered

searchSoftwareBreakpoints(PVOID mAddress):

    Searches for software breakpoints in the memory at the specified address (mAddress).
    It looks for the byte 0xCC (int 3), which is a common opcode used for software breakpoints.

searchHardwareBreakpoints(HANDLE tHandle):

    Checks for the presence of hardware breakpoints in the specified thread (tHandle).
    Utilizes the CONTEXT structure and the thread's context to inspect debug registers.

debuggerPresent():

    Uses the WinAPI function IsDebuggerPresent() to check if the process is being debugged.

antiDbgBreakPoint():

    Attempts to disable the DbgBreakPoint function by changing its first byte to 0xC3 (ret) using VirtualProtect.

antiDbgUiRemoteBreakin():

    Attempts to modify the DbgUiRemoteBreakin function to prevent remote debugging.
    Creates a custom patch (DbgUiRemoteBreakinPatch) and applies it to the DbgUiRemoteBreakin function.
![image](https://github.com/S12cybersecurity/AntiDebugging/assets/79543461/8fcc5067-b949-42f3-9173-8432f78711f7)


isDebuggerPresentInRemoteProcess(HANDLE hProcess):

    Checks if a debugger is present in a remote process specified by the hProcess handle.
    Uses the CheckRemoteDebuggerPresent function.

patchDebuggingFunctions():

    Calls both antiDbgBreakPoint() and antiDbgUiRemoteBreakin() to apply the patches.
