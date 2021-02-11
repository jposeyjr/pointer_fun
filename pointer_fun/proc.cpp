#include "proc.h"


//use DWORD because the process id is one in windows
DWORD GetProcId(const wchar_t* procName) {
	DWORD procId = 0; //error checking 
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //getting a snapchat or process
	if (hSnap != INVALID_HANDLE_VALUE) {//make sure it is valid 
		PROCESSENTRY32 procEntery; //save the process id 
		procEntery.dwSize = sizeof(procEntery); //set size to make sure it works

		if (Process32First(hSnap, &procEntery)) { //grabs first process and stores it 
			do
			{
				if (!_wcsicmp(procEntery.szExeFile, procName)) {
					procId = procEntery.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnap, &procEntery)); //looping through them all process id's until we find the one we want
		}
	}
	CloseHandle(hSnap); //prevent memory leaks
	return procId;//close and returns the id to us 
}


uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName) {
	uintptr_t modBaseAddr = 0; 
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (hSnap != INVALID_HANDLE_VALUE) {
		MODULEENTRY32 modEntry; 
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnap, &modEntry)) {
			do
			{
				if (!_wcsicmp(modEntry.szModule, modName)) {//just a compare string 
					modBaseAddr = (uintptr_t)modEntry.modBaseAddr; //casting to uintptr_t to make it work as its a BYTE * type 
					break;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
	}
	CloseHandle(hSnap); //prevent memory leaks
	return modBaseAddr; //return the base address  
}

//process handle, base pointer and a vector to hold offsets 
uintptr_t FindDMAAddy(HANDLE hProc, uintptr_t ptr, std::vector<unsigned int> offsets) {
	uintptr_t addr = ptr; //grabs pointer value 

	for (unsigned int i = 0; i < offsets.size(); i++) //loop through base pointer
	{
		//read what in the address 
		ReadProcessMemory(hProc, (BYTE*)addr, &addr, sizeof(addr), 0); 
		addr += offsets[i]; //adds the offset and loop through again 
	}
	return addr; //once it is done it will return the address of the value we need 
}
