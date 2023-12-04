#include <Windows.h>
#include <iostream>

using namespace std;

class AntiDebugging{
	public:
		struct DbgUiRemoteBreakinPatch
		{
			WORD  push_0;
			BYTE  push;
			DWORD CurrentPorcessHandle;
			BYTE  mov_eax;
			DWORD TerminateProcess;
			WORD  call_eax;
		};
		// Constructor
		AntiDebugging();

		// Methods
		bool searchSoftwareBreakpoints(PVOID mAddress) {
			PBYTE pBytes = (PBYTE)mAddress;
			// Search for RET (0xC3)
			for (SIZE_T i = 0; ; i++) {
				if (pBytes[i] == 0xCC) {
					return true;
				}
			}
			return false;
		}

		bool searchHardwareBreakpoints(HANDLE tHandle) {
			CONTEXT ctx;
			ZeroMemory(&ctx, sizeof(&ctx));
			ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

			GetThreadContext(tHandle, &ctx);
			return (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) ? true : false;
		}

		bool debuggerPresent() {
			return IsDebuggerPresent();
		}

		bool antiDbgBreakPoint() {
			FARPROC pDbgBreakPoint = GetProcAddress(GetModuleHandleA("ntdll.dll"), "DbgBreakPoint");
			if (!pDbgBreakPoint) {
				return false;
			}
			DWORD oldProtect;
			VirtualProtect(pDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
			*(PBYTE)pDbgBreakPoint = (BYTE)0xC3;
			return true;
		}

		bool antiDbgUiRemoteBreakin() {
			FARPROC pDbgUiRemoteBreakin = GetProcAddress(GetModuleHandleA("ntdll.dll"), "DbgUiRemoteBreakin");
			FARPROC pTerminateProcess = GetProcAddress(GetModuleHandleA("kernel32.dll"), "TerminateProcess");

			DbgUiRemoteBreakinPatch patch = { 0 };
			patch.push_0 = '\x6A\x00';
			patch.push = '\x68';
			patch.CurrentPorcessHandle = 0xFFFFFFFF;
			patch.mov_eax = '\xB8';
			patch.TerminateProcess = (DWORD)pTerminateProcess;
			patch.call_eax = '\xFF\xD0';

			DWORD oldProtect;
			VirtualProtect(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch), PAGE_READWRITE, &oldProtect);

			memcpy(pDbgUiRemoteBreakin, &patch, sizeof(DbgUiRemoteBreakinPatch));
			VirtualProtect(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch), oldProtect, &oldProtect);
			return true;
		}

		bool isDebuggerPresentInRemoteProcess(HANDLE hProcess) {
			bool isDebuggerPresent = false;
			CheckRemoteDebuggerPresent(hProcess, (PBOOL)isDebuggerPresent);
			return isDebuggerPresent;
		}
			

		bool patchDebuggingFunctions() {
			antiDbgBreakPoint();
			antiDbgUiRemoteBreakin();
		}

};