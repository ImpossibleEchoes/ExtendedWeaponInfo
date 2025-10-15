// dllmain.cpp : Defines the entry point for the DLL application.
#include "Windows.h"

#include "injector/injector.hpp"
#include "Hooking.Patterns-master/Hooking.Patterns.h"

#define NUM_WEAPON_INFO 0xFF

uint32_t g_weapHashId[NUM_WEAPON_INFO];
uint32_t g_numWeapHashId = 0;

uint32_t* g_origHashes = nullptr;

struct CWeaponInfo {
	uint8_t __0[0x110];

	static void* ms_reset;

	__forceinline void reset() { ((void(__thiscall*)(CWeaponInfo*))(ms_reset)) (this); }

};
void* CWeaponInfo::ms_reset;

CWeaponInfo g_weapInfo[NUM_WEAPON_INFO];

void initNewWeaponHashes() {
	do {
		//g_weapInfo[g_numWeapHashId].reset();
		g_weapHashId[g_numWeapHashId++] = *g_origHashes;
		g_origHashes++;
	} while (*g_origHashes);
}

CWeaponInfo* __cdecl getWeaponInfo(int a1) {
	if (g_numWeapHashId == 0)
		initNewWeaponHashes();

	if (a1 >= g_numWeapHashId)
		return g_weapInfo;
	else
		return &g_weapInfo[a1];
}


int __cdecl getWeaponInfoIdByHash(int hash, int _default = 55) {
	if (g_numWeapHashId == 0)
		initNewWeaponHashes();
	for (size_t i = 0; i < g_numWeapHashId; i++)
		if (hash == g_weapHashId[i])
			return i;


	if (_default <= 0) {
		_default = g_numWeapHashId;
		//g_weapInfo[g_numWeapHashId].reset();
		g_weapHashId[g_numWeapHashId++] = hash;
	}

	return _default;
}

bool patch() {
	auto pWeap = g_weapInfo;
	//auto pattern = hook::pattern("8B 44 24 04 83 F8 ?? 7D 0C 69 C0 ? ? ? ? 05 ? ? ? ? C3 B8 ? ? ? ? C3 ");
	auto pattern = hook::pattern("? ? ? ? ? ? ? 7D 0C 69 C0 ? ? ? ? 05 ? ? ? ? C3 B8 ? ? ? ? C3 "); // CE/<CE
	if (!pattern.empty()) {
		injector::WriteMemory(pattern.get_first(0xF + 1), pWeap, true);
		injector::WriteMemory(pattern.get_first(0x15 + 1), pWeap, true);
	}
	else 
		return false;

	pattern = hook::pattern("E8 ? ? ? ? 46 83 FE ? 7C EA 81 0D ? ? ? ? ? ? ? ? "); // CE
	if (pattern.empty())
		pattern = hook::pattern("E8 ? ? ? ? 83 C6 01 83 FE 3C 7C E8 B8 ? ? ? ? 09 05 ? ? ? ? "); // <CE
	if (!pattern.empty())
		CWeaponInfo::ms_reset = injector::GetBranchDestination(pattern.get_first()).get_raw<void>();
	else
		return false;


	pattern = hook::pattern("81 ? ? ? ? ? 89 ? 8B ? 1C 85 F6 74 ? "); // CE/<CE
	if (!pattern.empty())
		injector::WriteMemory(pattern.get_first(2), pWeap, true);
	else
		return false;

	pattern = hook::pattern("B9 ? ? ? ? ? ? ? ? ? EB 03 8D 49 00 E8 ? ? ? ? 81 C1 ? ? ? ? "); // <CE
	if (pattern.empty())
		pattern = hook::pattern("BE ? ? ? ? BF ? ? ? ? 8D 64 24 00 8B CE E8 ? ? ? ? 81 C6 10 01 00 00 4F 79 F0 68 ? ? ? ? E8 ? ? ? ? 83 C4 04 5F 5E C3 "); // CE
	if (!pattern.empty()) {
		injector::WriteMemory(pattern.get_first(1), pWeap, true);
		injector::WriteMemory<size_t>(pattern.get_first(6), sizeof g_weapInfo / sizeof *g_weapInfo, true);
	}
	else
		return false;
	
	pattern = hook::pattern("A3 ? ? ? ? E8 ? ? ? ? 8B 15 ? ? ? ? 6A 00 52 A3 ? ? ? ? E8 ? ? ? ? "); // <CE
	if (pattern.empty())
		pattern = hook::pattern("A3 ? ? ? ? E8 ? ? ? ? 6A 00 FF 35 ? ? ? ? A3 ? ? ? ? E8 ? ? ? ? 6A 00 FF 35 ? ? ? ? A3 ? ? ? ? "); // CE
	if (!pattern.empty())
		g_origHashes = injector::ReadMemory<uint32_t*>(pattern.get(0).get<void>(1), true);
	else
		return false;

	pattern = hook::pattern("? ? ? ? ? C0 3B 0C 85 ? ? ? ? 74 0C ");
	if (pattern.empty())
		pattern = hook::pattern("? ? ? ? ? C0 3B 0C 85 ? ? ? ? 74 0A 40 ");
	if (!pattern.empty()) 
		injector::MakeJMP(pattern.get_first(), reinterpret_cast<size_t>(getWeaponInfoIdByHash), true);
	else
		return false;

	void* ptr = 0;
	pattern = hook::pattern("? ? ? ? ? F8 ? 7D 0C 69 C0 ? ? ? ? 05 ? ? ? ? C3 "); // CE/<CE
	if (pattern.empty()) {
		pattern = hook::pattern("E8 ? ? ? ? 8B 48 04 8A 47 1C 83 C4 04 3A 46 1C "); // CE second. unused now
		if(!pattern.empty())
			ptr = injector::GetBranchDestination(pattern.get_first()).get_raw<void>();
	}
	else
		ptr = pattern.get_first();

	if (ptr)
		injector::MakeJMP(ptr, reinterpret_cast<size_t>(getWeaponInfo), true);
	else
		return false;

	return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		if(!patch())
			MessageBoxA(nullptr, "Addresses could not be determined", "ExtendedWeaponInfo", 0x10);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

