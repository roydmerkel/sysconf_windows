#include <windows.h>
#include <lmcons.h>
#include <time.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <winreg.h>

// Check windows
#if !defined(_WIN32) && !defined(_WIN16) && !defined(_WIN64)
#if WIN16 || _WIN16_ || ___WIN16 || ___WIN16__ || WIN32 || _WIN32_ || ___WIN32 || ___WIN32__ || WIN64 || _WIN64_ || ___WIN64 || ___WIN64__
#if WIN64 || _WIN64_ || ___WIN64 || ___WIN64__
#define _WIN64
#elif WIN16 || _WIN16_ || ___WIN16 || ___WIN16__
#define _WIN16
#else
#define _WIN32
#endif
#endif
#endif

// Check GCC
#if !defined(_WIN32) && !defined(_WIN16) && !defined(_WIN64)
#if __GNUC__
#if __x86_64__ || __ppc64__
#define _WIN64
#else
#define _WIN32
#endif
#endif
#endif

#ifdef _WIN64
#include <mfobjects.h>
#endif

//using namespace std;

#ifndef MAX
#define MAX(A, B) (((A) > (B)) ? (A) : (B)) 
#endif

#ifndef TEXT
	#ifndef __TEXT
		#ifdef  UNICODE                     // r_winnt
			#define __TEXT(quote) L##quote      // r_winnt
		#else   /* UNICODE */               // r_winnt
			#define __TEXT(quote) quote         // r_winnt
		#endif /* UNICODE */                // r_winnt
	#endif
	#define TEXT(quote) __TEXT(quote)   // r_winnt
#endif

#ifndef RE_DUP_MAX
#define RE_DUP_MAX 255
#endif

/* TODO: found this through ReactOS limits.h, couldn't find through any official windows sources and no idea what the equivelent function
   would be*/
#ifndef COLL_WEIGHTS_MAX 
#define COLL_WEIGHTS_MAX 2
#endif

#ifndef SYMLOOP_MAX // shamelessly stolen from Linux as Windows doesn't have symlinks separate from cygwin
	#ifdef MAXSYMLINKS
		#define SYMLOOP_MAX MAXSYMLINKS
	#else
		#define SYMLOOP_MAX 8
	#endif
#endif

typedef struct _LMEMORYSTATUSEX {
	DWORD dwLength;
	DWORD dwMemoryLoad;
	DWORDLONG ullTotalPhys;
	DWORDLONG ullAvailPhys;
	DWORDLONG ullTotalPageFile;
	DWORDLONG ullAvailPageFile;
	DWORDLONG ullTotalVirtual;
	DWORDLONG ullAvailVirtual;
	DWORDLONG ullAvailExtendedVirtual;
} LMEMORYSTATUSEX;

typedef LMEMORYSTATUSEX * PLMEMORYSTATUSEX;
typedef LMEMORYSTATUSEX FAR * LPLMEMORYSTATUSEX;

typedef struct _LOSVERSIONINFOEXW {
  DWORD dwOSVersionInfoSize;
  DWORD dwMajorVersion;
  DWORD dwMinorVersion;
  DWORD dwBuildNumber;
  DWORD dwPlatformId;
  WCHAR szCSDVersion[128];
  WORD  wServicePackMajor;
  WORD  wServicePackMinor;
  WORD  wSuiteMask;
  BYTE  wProductType;
  BYTE  wReserved;
} LOSVERSIONINFOEXW;

typedef struct _LOSVERSIONINFOEXA {
  DWORD dwOSVersionInfoSize;
  DWORD dwMajorVersion;
  DWORD dwMinorVersion;
  DWORD dwBuildNumber;
  DWORD dwPlatformId;
  CHAR  szCSDVersion[128];
  WORD  wServicePackMajor;
  WORD  wServicePackMinor;
  WORD  wSuiteMask;
  BYTE  wProductType;
  BYTE  wReserved;
} LOSVERSIONINFOEXA;

typedef struct _LOSVERSIONINFOA {
  DWORD dwOSVersionInfoSize;
  DWORD dwMajorVersion;
  DWORD dwMinorVersion;
  DWORD dwBuildNumber;
  DWORD dwPlatformId;
  CHAR  szCSDVersion[128];
} LOSVERSIONINFOA;

typedef struct _LOSVERSIONINFOW {
  DWORD dwOSVersionInfoSize;
  DWORD dwMajorVersion;
  DWORD dwMinorVersion;
  DWORD dwBuildNumber;
  DWORD dwPlatformId;
  WCHAR szCSDVersion[128];
} LOSVERSIONINFOW;

// workarround for NT 3.X compilers not defining correctly...
typedef struct _LSYSTEM_INFO {
    union {
        DWORD dwOemId;          // Obsolete field...do not use
        struct {
            WORD wProcessorArchitecture;
            WORD wReserved;
        } DUMMYSTRUCT;
    } DUMMYUNION;
    DWORD dwPageSize;
    LPVOID lpMinimumApplicationAddress;
    LPVOID lpMaximumApplicationAddress;
    DWORD dwActiveProcessorMask;
    DWORD dwNumberOfProcessors;
    DWORD dwProcessorType;
    DWORD dwAllocationGranularity;
    WORD wProcessorLevel;
    WORD wProcessorRevision;
} LSYSTEM_INFO;

typedef LSYSTEM_INFO * PLSYSTEM_INFO;
typedef LSYSTEM_INFO FAR * LPLSYSTEM_INFO;

typedef LONG NTSTATUS;
typedef LONG LSTATUS;
#define STATUS_SUCCESS 0x00000000L

typedef LOSVERSIONINFOEXA *PLOSVERSIONINFOEXA;
typedef LOSVERSIONINFOEXA FAR * LPLOSVERSIONINFOEXA;

typedef LOSVERSIONINFOEXW LRTL_OSVERSIONINFOEXW;
typedef LOSVERSIONINFOEXW *PLOSVERSIONINFOEXW;
typedef LOSVERSIONINFOEXW *PLRTL_OSVERSIONINFOEXW;

typedef LOSVERSIONINFOEXW FAR * LPLOSVERSIONINFOEXW;
typedef LOSVERSIONINFOEXW FAR * LPLRTL_OSVERSIONINFOEXW;

typedef LOSVERSIONINFOA * PLOSVERSIONINFOA;
typedef LOSVERSIONINFOA FAR * LPLOSVERSIONINFOA;

typedef LOSVERSIONINFOW LRTL_OSVERSIONINFOW;
typedef LOSVERSIONINFOW * PLOSVERSIONINFOW;
typedef LOSVERSIONINFOW *PLRTL_OSVERSIONINFOW;

typedef LOSVERSIONINFOW FAR * LPLOSVERSIONINFOW;
typedef LOSVERSIONINFOW FAR * LPLRTL_OSVERSIONINFOW;

typedef NTSTATUS (WINAPI *PRtlGetVersion)(PLRTL_OSVERSIONINFOW lpVersionInfo);
typedef NTSTATUS (WINAPI FAR *LPRtlGetVersion)(PLRTL_OSVERSIONINFOW lpVersionInfo);

typedef NTSTATUS (WINAPI *PRtlGetVersionEX)(PLRTL_OSVERSIONINFOEXW lpVersionInfo);
typedef NTSTATUS (WINAPI FAR *LPRtlGetVersionEX)(PLRTL_OSVERSIONINFOEXW lpVersionInfo);

typedef BOOL (WINAPI *PGetVersionEXA)(LPLOSVERSIONINFOA lpVersionInformation);
typedef BOOL (WINAPI FAR *LPGetVersionEXA)(LPLOSVERSIONINFOA lpVersionInformation);

typedef BOOL (WINAPI *PGetVersionEXEXA)(LPLOSVERSIONINFOEXA lpVersionInformation);
typedef BOOL (WINAPI FAR *LPGetVersionEXEXA)(LPLOSVERSIONINFOEXA lpVersionInformation);

typedef BOOL (WINAPI *PGlobalMemoryStatusEX)(LPLMEMORYSTATUSEX lpBuffer);
typedef BOOL (WINAPI FAR *LPGlobalMemoryStatusEX)(LPLMEMORYSTATUSEX lpBuffer);

typedef BOOL (WINAPI *PGlobalMemoryStatus)(LPMEMORYSTATUS lpBuffer);
typedef BOOL (WINAPI FAR *LPGlobalMemoryStatus)(LPMEMORYSTATUS lpBuffer);

typedef LSTATUS (WINAPI *PRegOpenKeyExA)(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
typedef LSTATUS (WINAPI FAR *LPRegOpenKeyExA)(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);

typedef LSTATUS (WINAPI *PRegQueryValueExA)(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
typedef LSTATUS (WINAPI FAR *LPRegQueryValueExA)(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
	
#ifndef REG_OPTION_OPEN_LINK
#define REG_OPTION_OPEN_LINK        (0x00000008L)   // Open symbolic link 
#endif

#ifndef READ_CONTROL
#define READ_CONTROL                     (0x00020000L)
#endif

#ifndef STANDARD_RIGHTS_READ
#define STANDARD_RIGHTS_READ             (READ_CONTROL)
#endif

#ifndef KEY_QUERY_VALUE
#define KEY_QUERY_VALUE         (0x0001)
#endif

#ifndef KEY_ENUMERATE_SUB_KEYS
#define KEY_ENUMERATE_SUB_KEYS  (0x0008)
#endif

#ifndef KEY_NOTIFY
#define KEY_NOTIFY              (0x0010)
#endif

#ifndef SYNCHRONIZE
#define SYNCHRONIZE                      (0x00100000L)
#endif

#ifndef KEY_READ
#define KEY_READ                ((STANDARD_RIGHTS_READ       |\
                                  KEY_QUERY_VALUE            |\
                                  KEY_ENUMERATE_SUB_KEYS     |\
                                  KEY_NOTIFY)                 \
                                  &                           \
                                 (~SYNCHRONIZE))
#endif

class GetWindowsInfo
{
	private:
		static SYSTEM_INFO systemInfo;
		static BOOL zSetSystemInfo;
		static HMODULE hKernel32;
		static HMODULE hAdvapi32;
		static HMODULE hNtDll;
		static FARPROC fpGetVersionEx;
		static FARPROC fpRtlGetVersion;
		static FARPROC fpGlobalMemoryStatusEx;
		static FARPROC fpGlobalMemoryStatus;
		static FARPROC fpRegOpenKeyExA;
		static FARPROC fpRegQueryValueExA;
		static int numInstances;
		static size_t zStackUsage;
		static BOOL zStackUsageSet;
		static BOOL zVersionInfoSet;
		static BOOL zIsNt;
		static BOOL zIsWin32s;
		static DWORD dwMajorVersion;
		static DWORD dwMinorVersion;
		static DWORD dwBuild;
		static DWORD dwPlatformId;
		static BYTE wProductType;

		static unsigned long mytol(LPCSTR str)
		{
			unsigned long t = 0;
			sscanf(str, "%lu", &t);
			
			return t;
		}

		static unsigned int mytoi(LPCSTR str)
		{
			unsigned long t = 0;
			sscanf(str, "%lu", &t);
			
			if(t >= UINT_MAX)
			{
				t = UINT_MAX;
			}
			
			return (unsigned int)t;
		}

		static unsigned short mytos(LPCSTR str)
		{
			unsigned long t = 0;
			sscanf(str, "%lu", &t);
			
			if(t >= USHRT_MAX)
			{
				t = USHRT_MAX;
			}
			
			return (unsigned short)t;
		}

		static unsigned char mytob(LPCSTR str)
		{
			unsigned long t = 0;
			sscanf(str, "%lu", &t);
			
			if(t >= UCHAR_MAX)
			{
				t = UCHAR_MAX;
			}
			
			return (unsigned char)t;
		}

		static int my_scprintf(const char * format, ...)
		{
			char *strBuf = NULL;
			int curSize = 0;
			int size = 0;
			va_list ap;
			
			va_start(ap, format);
			
			do
			{
				if(curSize == 0)
				{
					curSize = 1;
					strBuf = (char *)malloc(sizeof (char) * curSize);
				}
				else
				{
					curSize += 12;
					strBuf = (char *)realloc(strBuf, sizeof (char) * curSize);
				}
				
				if(strBuf == NULL)
				{
					size = 1;
				}
				else
				{
					size = _vsnprintf(strBuf, curSize - 1, format, ap);
				}
			} while(strBuf != NULL && size < 0);
			
			if(strBuf != NULL)
			{
				free(strBuf);
			}
			
			va_end(ap);
			
			return size - 1;
		}

	public:
		GetWindowsInfo()
		{
			if(numInstances == 0)
			{
				if(!zSetSystemInfo)
				{
					GetSystemInfo(&systemInfo);
					zSetSystemInfo = TRUE;
				}
				hNtDll = LoadLibrary(TEXT("NTDLL"));
				hKernel32 = LoadLibrary(TEXT("KERNEL32"));
				hAdvapi32 = LoadLibrary(TEXT("ADVAPI32"));

				if(hNtDll != 0)
				{
					fpRtlGetVersion = GetProcAddress(hNtDll, TEXT("RtlGetVersion"));
					if(fpRtlGetVersion != NULL)
					{
						zIsNt = TRUE;
						zIsWin32s = FALSE;
					}
				}

				if(hKernel32 != 0)
				{
					fpGetVersionEx = GetProcAddress(hKernel32, TEXT("GetVersionExA"));

					if(fpGetVersionEx == NULL)
					{
						fpGetVersionEx = GetProcAddress(hKernel32, TEXT("GetVersionEx"));
					}

					fpGlobalMemoryStatusEx = GetProcAddress(hKernel32, TEXT("GlobalMemoryStatusEx"));
					fpGlobalMemoryStatus = GetProcAddress(hKernel32, TEXT("GlobalMemoryStatus"));
				}
				
				if(hAdvapi32 != 0)
				{
					fpRegOpenKeyExA = GetProcAddress(hAdvapi32, TEXT("RegOpenKeyExA"));
					if(fpRegOpenKeyExA == NULL)
					{
						fpRegOpenKeyExA = GetProcAddress(hAdvapi32, TEXT("RegOpenKeyEx"));
					}
					
					fpRegQueryValueExA = GetProcAddress(hAdvapi32, TEXT("RegQueryValueExA"));
					if(fpRegQueryValueExA == NULL)
					{
						fpRegQueryValueExA = GetProcAddress(hAdvapi32, TEXT("RegQueryValueEx"));
					}
				}
				
				if(!zIsNt)
				{
					DWORD v = GetVersion();
					zIsNt = !(v & 0x80000000);
					zIsWin32s = ((!zIsNt) && (DWORD)(LOBYTE(LOWORD(v))) <= 3);
				}
				
				GetStackUsage();
			}
			numInstances++;
		}

		static BOOL GetWindowsRegistryKey(PHKEY phKeyCurrentVersion, PHKEY phKeyProductOptions)
		{
			BOOL success = FALSE;
			*phKeyCurrentVersion = 0;
			*phKeyProductOptions = 0;
			
			if(fpRegOpenKeyExA)
			{
				LSTATUS regOpenStatus = 0;
				HKEY hKeyOut = 0;
				
				regOpenStatus = ((LPRegOpenKeyExA)fpRegOpenKeyExA)(HKEY_LOCAL_MACHINE,
											TEXT("Software\\Microsoft\\Windows\\CurrentVersion"),
											REG_OPTION_OPEN_LINK,
											KEY_READ,
											&hKeyOut);
											
				if(regOpenStatus == 0)
				{
					*phKeyCurrentVersion = hKeyOut;
					success = TRUE;
				}
				
				regOpenStatus = ((LPRegOpenKeyExA)fpRegOpenKeyExA)(HKEY_LOCAL_MACHINE,
											TEXT("SYSTEM\\CurrentControlSet\\Control\\ProductOptions"),
											REG_OPTION_OPEN_LINK,
											KEY_READ,
											&hKeyOut);
												
				if(regOpenStatus == 0)
				{
					*phKeyProductOptions = hKeyOut;
					success = TRUE;
				}
			}
			
			return success;
		}
		
		static BOOL ReadWindowsRegistryValue(PHKEY parent, LPCSTR value, HLOCAL *pdataHandle, LPBYTE *pdata)
		{
			BOOL result = FALSE;
			HLOCAL dataHandle = 0;
			LPBYTE data = NULL;
			DWORD dataSize = 256;
			
			*pdataHandle = 0;
			*pdata = NULL;
			
			if(fpRegQueryValueExA != NULL)
			{
				DWORD dwType;
				dataHandle = LocalAlloc(LMEM_FIXED, dataSize);
				
				if(dataHandle != 0)
				{
					LSTATUS status = 0;
					data = (LPBYTE)LocalLock(dataHandle);
					
					if(data != 0)
					{
						status = ((LPRegQueryValueExA)fpRegQueryValueExA)(*parent, value, NULL, &dwType, data, &dataSize);
						
						while(status == ERROR_MORE_DATA)
						{
							LocalUnlock(data);
							data = NULL;
							dataSize += 256;
							
							dataHandle = LocalReAlloc(dataHandle, dataSize, LMEM_ZEROINIT);
							
							if(dataHandle != 0)
							{
								data = (LPBYTE)LocalLock(dataHandle);
								
								if(data != 0)
								{
									status = ((LPRegQueryValueExA)fpRegQueryValueExA)(*parent, value, NULL, &dwType, data, &dataSize);
								}
							}
						}
					}
						
					if(data != NULL && status == 0)
					{
						HLOCAL envStrHandle = 0;
						LPSTR envStr = NULL;
						DWORD nSize = 0;
						DWORD tmp1;
						//QWORD tmp2;
						char t;
						
						if(dwType == REG_BINARY)
						{
							result = TRUE;
							*pdata = data;
							*pdataHandle = dataHandle;
						}
						else if(dwType == REG_DWORD)
						{
							tmp1 = *((DWORD*)data);
							nSize = my_scprintf("%lu", (unsigned long)tmp1);
							
							if(nSize > 0)
							{
								envStrHandle = LocalAlloc(LMEM_FIXED, (nSize + 1) * sizeof (char));
								
								if(envStrHandle != 0)
								{
									envStr = (LPSTR)LocalLock(envStrHandle);
									
									if(envStr != NULL)
									{
										result = TRUE;
										wsprintfA(envStr, "%lu", (unsigned long)tmp1);
										*pdata = (LPBYTE)envStr;
										*pdataHandle = envStrHandle;
									}
									else
									{
										LocalFree(envStrHandle);
										envStrHandle = NULL;
									}
								}
								
								LocalUnlock(data);
								data = NULL;
								LocalFree(dataHandle);
								dataHandle = 0;
							}
						}
						else if(dwType == REG_DWORD_LITTLE_ENDIAN)
						{
							tmp1 = ((DWORD)(((BYTE *)data)[3]) << 24) | 
									((DWORD)(((BYTE *)data)[2]) << 16) | 
									((DWORD)(((BYTE *)data)[1]) << 8) | 
									((DWORD)(((BYTE *)data)[0]));
							nSize = my_scprintf("%lu", (unsigned long)tmp1);
							
							if(nSize > 0)
							{
								envStrHandle = LocalAlloc(LMEM_FIXED, (nSize + 1) * sizeof (char));
								
								if(envStrHandle != 0)
								{
									envStr = (LPSTR)LocalLock(envStrHandle);
									
									if(envStr != NULL)
									{
										result = TRUE;
										wsprintfA(envStr, "%lu", (unsigned long)tmp1);
										*pdata = (LPBYTE)envStr;
										*pdataHandle = envStrHandle;
									}
									else
									{
										LocalFree(envStrHandle);
										envStrHandle = NULL;
									}
								}
								
								LocalUnlock(data);
								data = NULL;
								LocalFree(dataHandle);
								dataHandle = 0;
							}
						}
						else if(dwType == REG_DWORD_BIG_ENDIAN)
						{
							tmp1 = ((DWORD)(((BYTE *)data)[0]) << 24) | 
									((DWORD)(((BYTE *)data)[1]) << 16) | 
									((DWORD)(((BYTE *)data)[2]) << 8) | 
									((DWORD)(((BYTE *)data)[3]));
							nSize = my_scprintf("%lu", (unsigned long)tmp1);
							
							if(nSize > 0)
							{
								envStrHandle = LocalAlloc(LMEM_FIXED, (nSize + 1) * sizeof (char));
								
								if(envStrHandle != 0)
								{
									envStr = (LPSTR)LocalLock(envStrHandle);
									
									if(envStr != NULL)
									{
										result = TRUE;
										wsprintfA(envStr, "%lu", (unsigned long)tmp1);
										*pdata = (LPBYTE)envStr;
										*pdataHandle = envStrHandle;
									}
									else
									{
										LocalFree(envStrHandle);
										envStrHandle = NULL;
									}
								}
								
								LocalUnlock(data);
								data = NULL;
								LocalFree(dataHandle);
								dataHandle = 0;
							}
						}
						else if(dwType == REG_EXPAND_SZ)
						{
							nSize = ExpandEnvironmentStringsA((LPCSTR)data, &t, nSize);
							
							envStrHandle = LocalAlloc(LMEM_FIXED, nSize);
							
							if(envStrHandle != 0)
							{
								envStr = (LPSTR)LocalLock(envStrHandle);
								
								if(envStr != NULL)
								{
									ExpandEnvironmentStringsA((LPCSTR)data, envStr, nSize);
									
									result = TRUE;
									*pdata = (LPBYTE)envStr;
									*pdataHandle = envStrHandle;
								}
							}
								
							LocalUnlock(data);
							data = NULL;
							LocalFree(dataHandle);
							dataHandle = 0;
						}
						else if(dwType == REG_LINK)
						{
							result = TRUE;
							*pdata = data;
							*pdataHandle = dataHandle;
						}
						else if(dwType == REG_MULTI_SZ)
						{
							result = TRUE;
							*pdata = data;
							*pdataHandle = dataHandle;
						}
						else if(dwType == REG_NONE)
						{
							result = TRUE;
							*pdata = NULL;
							*pdataHandle = 0;
								
							LocalUnlock(data);
							data = NULL;
							LocalFree(dataHandle);
							dataHandle = 0;
						}
						#ifdef REG_QWORD
						else if(dwType == REG_QWORD)
						{
						}
						#endif
						#ifdef REG_QWORD_LITTLE_ENDIAN
						else if(dwType == REG_QWORD_LITTLE_ENDIAN)
						{
						}
						#endif
						else if(dwType == REG_SZ)
						{
							result = TRUE;
							*pdata = data;
							*pdataHandle = dataHandle;
						}
					}
				}
			}
			
			return result;
		}
		
		static void GetWindowsVersion(DWORD &minorVersion, DWORD &majorVersion, DWORD &build, DWORD &platformId, BYTE &productType, BOOL &isNT, BOOL &isWin32s, WORD &processorArchitecture)
		{
			if(!zVersionInfoSet)
			{
				BOOL success = FALSE;

				majorVersion = 0;
				minorVersion = 0;
				build = 0;
				dwBuild = 0;
				dwPlatformId = 0;
				dwMajorVersion = 0;
				dwMinorVersion = 0;
				wProductType = 0;
				
				if(!success && fpRtlGetVersion != NULL)
				{
					LRTL_OSVERSIONINFOEXW osversioninfo;
					memset(&osversioninfo, '\0', sizeof (LRTL_OSVERSIONINFOEXW));
					osversioninfo.dwOSVersionInfoSize = sizeof (LRTL_OSVERSIONINFOEXW);
					NTSTATUS status = ((LPRtlGetVersionEX)fpRtlGetVersion)(&osversioninfo);
					if(status == STATUS_SUCCESS)
					{
						success = TRUE;
						majorVersion = osversioninfo.dwMajorVersion;
						minorVersion = osversioninfo.dwMinorVersion;
						build = osversioninfo.dwBuildNumber;
						platformId = osversioninfo.dwPlatformId;
						productType = osversioninfo.wProductType;
						
						dwMajorVersion = majorVersion;
						dwMinorVersion = minorVersion;
						dwBuild = build;
						dwPlatformId = platformId;
						wProductType = productType;
						
						zVersionInfoSet = TRUE;
					}
				}

				if(!success && fpGetVersionEx != NULL)
				{
					LOSVERSIONINFOEXA versionInformation;
					memset(&versionInformation, '\0', sizeof (LOSVERSIONINFOEXA));
					versionInformation.dwOSVersionInfoSize = sizeof (LOSVERSIONINFOEXA);
					success = ((LPGetVersionEXEXA)fpGetVersionEx)(&versionInformation);
					if(success)
					{
						majorVersion = versionInformation.dwMajorVersion;
						minorVersion = versionInformation.dwMinorVersion;
						build = versionInformation.dwBuildNumber;
						platformId = versionInformation.dwPlatformId;
						productType = versionInformation.wProductType;
						
						dwMajorVersion = majorVersion;
						dwMinorVersion = minorVersion;
						dwBuild = build;
						dwPlatformId = platformId;
						wProductType = productType;
						
						zVersionInfoSet = TRUE;
					}
				}

				if(!success && fpRtlGetVersion != NULL)
				{
					LRTL_OSVERSIONINFOW osversioninfo;
					memset(&osversioninfo, '\0', sizeof (LRTL_OSVERSIONINFOW));
					osversioninfo.dwOSVersionInfoSize = sizeof (LRTL_OSVERSIONINFOW);
					NTSTATUS status = ((LPRtlGetVersion)fpRtlGetVersion)(&osversioninfo);
					if(status == STATUS_SUCCESS)
					{
						HKEY hKeyCurrentVersion = 0;
						HKEY hKeyProductOptions = 0;
						
						success = TRUE;
						majorVersion = osversioninfo.dwMajorVersion;
						minorVersion = osversioninfo.dwMinorVersion;
						build = osversioninfo.dwBuildNumber;
						platformId = osversioninfo.dwPlatformId;
						
						dwMajorVersion = majorVersion;
						dwMinorVersion = minorVersion;
						dwBuild = build;
						dwPlatformId = platformId;
						productType = 0;
						
						GetWindowsRegistryKey(&hKeyCurrentVersion, &hKeyProductOptions);
						
						if(productType == 0 && hKeyCurrentVersion != 0)
						{
							HLOCAL dataHandle = NULL;
							LPBYTE data;
							
							if(ReadWindowsRegistryValue(&hKeyCurrentVersion, "ProductType", &dataHandle, &data))
							{
								productType = mytob((LPSTR)data);
								
								LocalUnlock(data);
								data = NULL;
								LocalFree(dataHandle);
								dataHandle = 0;
							}
						}
						if(productType == 0 && hKeyProductOptions != 0)
						{
							HLOCAL dataHandle = NULL;
							LPBYTE data;
							
							if(ReadWindowsRegistryValue(&hKeyProductOptions, "ProductType", &dataHandle, &data))
							{
								if(lstrcmpiA((LPCSTR)data, "WINNT") == 0)
								{
									productType = 1;
								}
								else if (lstrcmpiA((LPCSTR)data, "LANMANNT") == 0)
								{
									productType = 2;
								}
								else if (lstrcmpiA((LPCSTR)data, "SERVERNT") == 0)
								{
									productType = 3;
								}
								
								LocalUnlock(data);
								data = NULL;
								LocalFree(dataHandle);
								dataHandle = 0;
							}
						}
						
						if(hKeyCurrentVersion != 0)
						{
							RegCloseKey(hKeyCurrentVersion);
						}
						
						if(hKeyProductOptions != 0)
						{
							RegCloseKey(hKeyProductOptions);
						}
						
						wProductType = productType;
						
						zVersionInfoSet = TRUE;
					}
				}

				if(!success && fpGetVersionEx != NULL)
				{
					LOSVERSIONINFOA versionInformation;
					memset(&versionInformation, '\0', sizeof (LOSVERSIONINFOA));
					versionInformation.dwOSVersionInfoSize = sizeof (LOSVERSIONINFOA);
					success = ((LPGetVersionEXA)fpGetVersionEx)(&versionInformation);
					if(success)
					{
						HKEY hKeyCurrentVersion = 0;
						HKEY hKeyProductOptions = 0;
						
						/* for win32S, GetVersionEx returns the version of win32s, so a separate call to GetVersion will be required. */
						if(zIsWin32s || versionInformation.dwMajorVersion < 3)
						{
							DWORD dwVersion = GetVersion();
							
							majorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
							minorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

							build = 0;
							if(dwVersion < 0x80000000)
							{
								build = (DWORD)(HIWORD(dwVersion));
							}
							
							platformId = 0;
						}
						else
						{
							majorVersion = versionInformation.dwMajorVersion;
							minorVersion = versionInformation.dwMinorVersion;
							build = versionInformation.dwBuildNumber;
							platformId = versionInformation.dwPlatformId;
						}
						
						dwMajorVersion = majorVersion;
						dwMinorVersion = minorVersion;
						dwBuild = build;
						dwPlatformId = platformId;
						productType = 0;
						
						GetWindowsRegistryKey(&hKeyCurrentVersion, &hKeyProductOptions);
						
						if(productType == 0 && hKeyCurrentVersion != 0)
						{
							HLOCAL dataHandle = NULL;
							LPBYTE data;
							
							if(ReadWindowsRegistryValue(&hKeyCurrentVersion, "ProductType", &dataHandle, &data))
							{
								productType = mytob((LPSTR)data);
								
								LocalUnlock(data);
								data = NULL;
								LocalFree(dataHandle);
								dataHandle = 0;
							}
						}
						if(productType == 0 && hKeyProductOptions != 0)
						{
							HLOCAL dataHandle = NULL;
							LPBYTE data;
							
							if(ReadWindowsRegistryValue(&hKeyProductOptions, "ProductType", &dataHandle, &data))
							{
								if(lstrcmpiA((LPCSTR)data, "WINNT") == 0)
								{
									productType = 1;
								}
								else if (lstrcmpiA((LPCSTR)data, "LANMANNT") == 0)
								{
									productType = 2;
								}
								else if (lstrcmpiA((LPCSTR)data, "SERVERNT") == 0)
								{
									productType = 3;
								}
								
								LocalUnlock(data);
								data = NULL;
								LocalFree(dataHandle);
								dataHandle = 0;
							}
						}
						
						if(hKeyCurrentVersion != 0)
						{
							RegCloseKey(hKeyCurrentVersion);
						}
						
						if(hKeyProductOptions != 0)
						{
							RegCloseKey(hKeyProductOptions);
						}
						
						wProductType = productType;
						
						zVersionInfoSet = TRUE;
					}
				}

				if(!success)
				{
					HKEY hKeyCurrentVersion = 0;
					HKEY hKeyProductOptions = 0;
					DWORD dwVersion = 0;
					BOOL isNT = FALSE;

					dwVersion = GetVersion();

					majorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
					minorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

					if(dwVersion < 0x80000000)
					{
						build = (DWORD)(HIWORD(dwVersion));
						
						dwBuild = build;
					}
					
					productType = 0;
					
					platformId = 0;
					
					dwMajorVersion = majorVersion;
					dwMinorVersion = minorVersion;
					
					GetWindowsRegistryKey(&hKeyCurrentVersion, &hKeyProductOptions);
					
					if(productType == 0 && hKeyCurrentVersion != 0)
					{
						HLOCAL dataHandle = NULL;
						LPBYTE data;
						
						if(ReadWindowsRegistryValue(&hKeyCurrentVersion, "ProductType", &dataHandle, &data))
						{
							productType = mytob((LPSTR)data);
							
							LocalUnlock(data);
							data = NULL;
							LocalFree(dataHandle);
							dataHandle = 0;
						}
					}
					if(productType == 0 && hKeyProductOptions != 0)
					{
						HLOCAL dataHandle = NULL;
						LPBYTE data;
						
						if(ReadWindowsRegistryValue(&hKeyProductOptions, "ProductType", &dataHandle, &data))
						{
							isNT = TRUE;
							if(lstrcmpiA((LPCSTR)data, "WINNT") == 0)
							{
								productType = 1;
							}
							else if (lstrcmpiA((LPCSTR)data, "LANMANNT") == 0)
							{
								productType = 2;
							}
							else if (lstrcmpiA((LPCSTR)data, "SERVERNT") == 0)
							{
								productType = 3;
							}
							
							LocalUnlock(data);
							data = NULL;
							LocalFree(dataHandle);
							dataHandle = 0;
						}
					}
					
					if(hKeyCurrentVersion != 0)
					{
						RegCloseKey(hKeyCurrentVersion);
					}
					
					if(hKeyProductOptions != 0)
					{
						RegCloseKey(hKeyProductOptions);
					}
					
					wProductType = productType;
					
					if(dwMajorVersion >= 3 && dwMinorVersion == 0x0a && zIsWin32s)
					{
						platformId = 0;
					}
					else if(dwMajorVersion >= 3 && (dwMinorVersion == 0x0a || dwMinorVersion == 0x32 || dwMinorVersion == 0x33))
					{
						platformId = 2;
					}
					else if(dwMajorVersion >= 4 && isNT)
					{
						platformId = 2;
					}
					else if(dwMajorVersion >= 4)
					{
						platformId = 1;
					}
					else
					{
						platformId = 0;
					}
					dwPlatformId = platformId;
					
					zVersionInfoSet = TRUE;
				}
				
				isNT = zIsNt;
				isWin32s = zIsWin32s;
				processorArchitecture = ((PLSYSTEM_INFO)(&systemInfo))->DUMMYUNION.DUMMYSTRUCT.wProcessorArchitecture;
			}
			else
			{
				majorVersion = dwMajorVersion;
				minorVersion = dwMinorVersion;
				build = dwBuild;
				platformId = dwPlatformId;
				productType = wProductType;
				
				isNT = zIsNt;
				isWin32s = zIsWin32s;
				processorArchitecture = ((PLSYSTEM_INFO)(&systemInfo))->DUMMYUNION.DUMMYSTRUCT.wProcessorArchitecture;
			}
		}

		static void GetPhysicalMemory(LPLMEMORYSTATUSEX status)
		{
			BOOL success = FALSE;
			if(!success && fpGlobalMemoryStatusEx != NULL)
			{
				LMEMORYSTATUSEX memStatus;
				memset(&memStatus, '\0', sizeof (memStatus));
				memStatus.dwLength = sizeof (memStatus);

				success = ((LPGlobalMemoryStatusEX)(fpGlobalMemoryStatusEx))(&memStatus);
				
				if(success)
				{
					*status = memStatus;
				}
			}
			if(!success && fpGlobalMemoryStatus != NULL)
			{
				MEMORYSTATUS memStatus;
				memset(&memStatus, '\0', sizeof (memStatus));
				memStatus.dwLength = sizeof (memStatus);

				((LPGlobalMemoryStatus)(fpGlobalMemoryStatus))(&memStatus);
				success = TRUE;
				if(success)
				{
					status->dwLength = memStatus.dwLength;
					status->dwMemoryLoad = memStatus.dwMemoryLoad;
					status->ullTotalPhys = memStatus.dwTotalPhys;
					status->ullAvailPhys = memStatus.dwAvailPhys;
					status->ullTotalPageFile = memStatus.dwTotalPageFile;
					status->ullAvailPageFile = memStatus.dwAvailPageFile;
					status->ullTotalVirtual = memStatus.dwTotalVirtual;
					status->ullAvailVirtual = memStatus.dwAvailVirtual;
					status->ullAvailExtendedVirtual = 0;
				}
			}
			if(!success)
			{
				ZeroMemory(&status, sizeof (LMEMORYSTATUSEX));
			}
		}

		~GetWindowsInfo()
		{
			numInstances--;
			if(numInstances == 0)
			{
				if(hNtDll != 0)
				{
					FreeLibrary(hNtDll);
					hNtDll = 0;
				}

				if(hKernel32 != 0)
				{
					FreeLibrary(hKernel32);
					hKernel32 = 0;
				}

				if(hAdvapi32 != 0)
				{
					FreeLibrary(hAdvapi32);
					hAdvapi32 = 0;
				}
				
				fpGetVersionEx = NULL;
				fpRtlGetVersion = NULL;
				fpGlobalMemoryStatusEx = NULL;
				fpGlobalMemoryStatus = NULL;
				fpRegOpenKeyExA = NULL;
				fpRegQueryValueExA = NULL;
			}
		}
		
		/* The following functio was copied, and editted from Boehm-Demers-Weiser conservative C/C++ Garbage Collector os_dep.c.
		 * This copy was done due to VirtualQuery not working the same in win32S. So this function uses a static global variable, instead,
		 * to pull memory.
		 * As such:
		 */
		/*
		 * Copyright 1988, 1989 Hans-J. Boehm, Alan J. Demers
		 * Copyright (c) 1991-1995 by Xerox Corporation.  All rights reserved.
		 * Copyright (c) 1996-1999 by Silicon Graphics.  All rights reserved.
		 * Copyright (c) 1999 by Hewlett-Packard Company.  All rights reserved.
		 *
		 * THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
		 * OR IMPLIED.  ANY USE IS AT YOUR OWN RISK.
		 *
		 * Permission is hereby granted to use or copy this program
		 * for any purpose,  provided the above notices are retained on all copies.
		 * Permission to modify the code and to distribute modified code is granted,
		 * provided the above notices are retained, and a notice that the code was
		 * modified is included with the above copyright notice.
		 */
		/* Return the smallest address a such that VirtualQuery               */
		/* returns correct results for all addresses between a and start.     */
		/* Assumes VirtualQuery returns correct information for start.        */
		static LPVOID GC_least_described_address(LPVOID start)
		{
			MEMORY_BASIC_INFORMATION buf;
			LPVOID limit;
			LPVOID p;

			limit = systemInfo.lpMinimumApplicationAddress;
			#ifdef _WIN64
			p = (LPVOID)((QWORD)start & ~(systemInfo.dwPageSize - 1));
			#else
			p = (LPVOID)((DWORD)start & ~(systemInfo.dwPageSize - 1));
			#endif
			for (;;) {
				size_t result;
				#ifdef _WIN64
				LPVOID q = (LPVOID)((QWORD)p - systemInfo.dwPageSize);
				#else
				LPVOID q = (LPVOID)((DWORD)p - systemInfo.dwPageSize);
				#endif

				#ifdef _WIN64
				if ((QWORD)q > (QWORD)p /* underflow */ || (QWORD)q < (QWORD)limit) break;
				#else
				if ((DWORD)q > (DWORD)p /* underflow */ || (DWORD)q < (DWORD)limit) break;
				#endif
				result = VirtualQuery(q, &buf, sizeof(buf));
				if (result != sizeof(buf) || buf.AllocationBase == 0) break;
				p = (LPVOID)(buf.AllocationBase);
			}
			return p;
		}
  
		static size_t GetStackUsage()
		{
			if(!zStackUsageSet)
			{
				LPVOID AllocationBase;
				MEMORY_BASIC_INFORMATION mbi;
				if(!zIsWin32s)
				{
					VirtualQuery(&mbi, &mbi, sizeof(mbi));
					AllocationBase = mbi.AllocationBase;
				}
				else
				{
					AllocationBase = GC_least_described_address(&zIsWin32s);
				}
				// now mbi.AllocationBase = reserved stack memory base address

				VirtualQuery(AllocationBase, &mbi, sizeof(mbi));
				// now (mbi.BaseAddress, mbi.RegionSize) describe reserved (uncommitted) portion of the stack
				// skip it

				VirtualQuery((char*)mbi.BaseAddress + mbi.RegionSize, &mbi, sizeof(mbi));
				// now (mbi.BaseAddress, mbi.RegionSize) describe the guard page
				// skip it

				VirtualQuery((char*)mbi.BaseAddress + mbi.RegionSize, &mbi, sizeof(mbi));
				// now (mbi.BaseAddress, mbi.RegionSize) describe the committed (i.e. accessed) portion of the stack

				zStackUsage = mbi.RegionSize;
				zStackUsageSet = TRUE;
			}
			return zStackUsage;
		}
		
		static void GetWindowsSystemInfo(PLSYSTEM_INFO FAR * pSystemInfo)
		{
			if(!zSetSystemInfo)
			{
				GetSystemInfo(&systemInfo);
				zSetSystemInfo = TRUE;
			}
			*pSystemInfo = ((PLSYSTEM_INFO)(&systemInfo));
		}
};

int GetWindowsInfo::numInstances = 0;
FARPROC GetWindowsInfo::fpGetVersionEx = NULL;
FARPROC GetWindowsInfo::fpRtlGetVersion = NULL;
FARPROC GetWindowsInfo::fpGlobalMemoryStatusEx = NULL;
FARPROC GetWindowsInfo::fpGlobalMemoryStatus = NULL;
FARPROC GetWindowsInfo::fpRegOpenKeyExA = NULL;
FARPROC GetWindowsInfo::fpRegQueryValueExA = NULL;
HMODULE GetWindowsInfo::hKernel32 = 0;
HMODULE GetWindowsInfo::hAdvapi32 = 0;
HMODULE GetWindowsInfo::hNtDll = 0;
size_t GetWindowsInfo::zStackUsage = 0;
BOOL GetWindowsInfo::zStackUsageSet = FALSE;
BOOL GetWindowsInfo::zVersionInfoSet = FALSE;
DWORD GetWindowsInfo::dwMajorVersion = 0;
DWORD GetWindowsInfo::dwMinorVersion = 0;
DWORD GetWindowsInfo::dwBuild = 0;
DWORD GetWindowsInfo::dwPlatformId = 0;
BYTE GetWindowsInfo::wProductType = 0;
BOOL GetWindowsInfo::zIsNt = FALSE;
BOOL GetWindowsInfo::zIsWin32s = FALSE;
SYSTEM_INFO GetWindowsInfo::systemInfo;
BOOL GetWindowsInfo::zSetSystemInfo = FALSE;

static GetWindowsInfo _getWindowsInfo;

static DWORD dWordnumberOfSetBits(DWORD i)
{
     // Java: use >>> instead of >>
     // C or C++: use uint32_t
     i = i - ((i >> 1) & 0x55555555);
     i = (i & 0x33333333) + ((i >> 2) & 0x33333333);
     return (((i + (i >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
}

/*static WORD wordnumberOfSetBits(WORD i)
{
     // Java: use >>> instead of >>
     // C or C++: use uint32_t
     i = i - ((i >> 1) & 0x5555);
     i = (i & 0x3333) + ((i >> 2) & 0x3333);
     i = (((i + (i >> 4)) & 0x0F0F) * 0x0101);
     return i >> 8;
}

static BYTE bytenumberOfSetBits(BYTE i)
{
     // Java: use >>> instead of >>
     // C or C++: use uint32_t
     i = i - ((i >> 1) & 0x55);
     i = (i & 0x33) + ((i >> 2) & 0x33);
     i = (((i + (i >> 4)) & 0x0F) * 0x01);
     return i;
}*/


#define _SC_ARG_MAX 0
#define _SC_CHILD_MAX 1
#define _SC_CLK_TCK 2
#define _SC_NGROUPS_MAX 3
#define _SC_OPEN_MAX 4
#define _SC_STREAM_MAX 5
#define _SC_TZNAME_MAX 6
#define _SC_VERSION 29
#define _SC_PAGESIZE 30
#define _SC_PAGE_SIZE 30
#define _SC_BC_BASE_MAX 36
#define _SC_BC_DIM_MAX 37
#define _SC_BC_SCALE_MAX 38
#define _SC_BC_STRING_MAX 39
#define _SC_COLL_WEIGHTS_MAX 40
#define _SC_EXPR_NEST_MAX 42
#define _SC_LINE_MAX 43
#define _SC_RE_DUP_MAX 44
#define _SC_2_VERSION 46
#define _SC_2_C_DEV 48
#define _SC_2_FORT_DEV 49
#define _SC_2_FORT_RUN 50
#define _SC_2_SW_DEV 51
#define _SC_2_LOCALEDEF 52
#define _SC_LOGIN_NAME_MAX 71
#define _SC_TTY_NAME_MAX 72
#define _SC_NPROCESSORS_CONF 83
#define _SC_NPROCESSORS_ONLN 84
#define _SC_PHYS_PAGES 85
#define _SC_AVPHYS_PAGES 86
#define _SC_SYMLOOP_MAX 173
#define _SC_HOST_NAME_MAX 180

long sysconf(int name)
{
        long retVal;

        switch(name)
        {
			case _SC_ARG_MAX:
				{
					// 64 - 1 max < windows 2000
					// 1020 - 1 max = windows NT 3.51, NT 4.0 Workstation
					// 1024 - 1 max = windows 2000
					// 4096 - 1 >= windows XP
					//retVal = ARG_MAX;
					DWORD dwMinorVersion;
					DWORD dwMajorVersion;
					DWORD dwBuild;
					DWORD dwPlatformId;
					BYTE wProductType;
					BOOL zIsNt;
					BOOL zIsWin32s;
					WORD wProcessorArchitecture;

					GetWindowsInfo::GetWindowsVersion(dwMinorVersion, dwMajorVersion, dwBuild, dwPlatformId, wProductType, zIsNt, zIsWin32s, wProcessorArchitecture);

					//508 - 1 for NT 3.1
					if(dwMajorVersion == 3 && dwMinorVersion == 0x0a && zIsWin32s)
					{
						retVal = 64 - 1;
					}
					else if(dwMajorVersion == 3 && (dwMinorVersion == 0x0a || dwMinorVersion == 0x32))
					{
						retVal = 508 - 1;
					}
					else if(dwMajorVersion == 3 && dwMinorVersion == 0x33)
					{
						retVal = 1020 - 1;
					}
					else if((dwMajorVersion == 4 && dwMinorVersion == 0 && dwPlatformId == 2) || (dwMajorVersion == 5 && dwMinorVersion == 0))
					{
						retVal = 1024 - 1;
					}
					else if(dwMajorVersion < 5)
					{
						retVal = 64 - 1;
					}
					else
					{
						retVal = 4096 - 1;
					}
				}
				break;
			case _SC_CHILD_MAX:
				{
					// get the amount of committed memory.
					// this is normally limited only by physical memory and the amount used by the stack
					// except in windows 9X where FS is shared for all processes so there is an additional
					// 8192 limit.
					// if we fail to get the stack usage, for some reason then use POSIX minimum of 25
					DWORD dwMinorVersion;
					DWORD dwMajorVersion;
					DWORD dwBuild;
					DWORD dwPlatformId;
					BYTE wProductType;
					BOOL zIsNt;
					BOOL zIsWin32s;
					WORD wProcessorArchitecture;
					LMEMORYSTATUSEX status;
					DWORDLONG maxChildren;
					size_t stackUsage;
					GetWindowsInfo::GetPhysicalMemory(&status);
					
					stackUsage = GetWindowsInfo::GetStackUsage();
					maxChildren = (stackUsage != 0) ? status.ullTotalPhys / stackUsage : 25; 

					GetWindowsInfo::GetWindowsVersion(dwMinorVersion, dwMajorVersion, dwBuild, dwPlatformId, wProductType, zIsNt, zIsWin32s, wProcessorArchitecture);

					if(dwMajorVersion < 3 || zIsWin32s || (dwMajorVersion == 3 && dwMinorVersion != 0x0a && dwMinorVersion != 0x32 && dwMinorVersion != 0x33) || (dwMajorVersion == 4 && (dwMinorVersion != 0 || dwPlatformId != 2)))
					{
						if(maxChildren == 0 || maxChildren > 8192)
						{
							maxChildren = 8192;
						}
					}

					if(maxChildren > LONG_MAX)
						maxChildren = LONG_MAX;

					retVal = (long)maxChildren;
				}
				break;
			case _SC_HOST_NAME_MAX:
				{
					retVal = 256;
				}
				break;
			case _SC_LOGIN_NAME_MAX:
				{
					retVal = UNLEN + 1;
				}
				break;
			case _SC_NGROUPS_MAX:
				{
					retVal = 1024;
				}
				break;
			case _SC_CLK_TCK:
				{
					retVal = CLK_TCK;
				}
				break;
			case _SC_OPEN_MAX:
				{
					// found experimentally:
					// Win 32s: 27 (512 MB memory, 243MB swap file)
					// NT 3.1: 4033 (64 MB memory, 999MB Swap file)
					// NT 3.5: 30676 (1024 MB memory 4000MB Swap File)
					// NT 3.51: 32403 (3.5GB, 3.5GB Swap File)
					// NT 4.0: 30069 (4.0GB, 3949MB Swap file)
					// NT 4.0 33013 (4.0GB, system swap file)
					// windows 95: 64967 (512MB memory, 2G swap file)
					// windows 98: 22527 (1GB memory, 4GB swap file)
					// windows ME: 20443 (1GB memory, 4GB swap file)
					// windows 2k: 300832 (4GB memory, 4GB swap file)
					// windows XP SP2 32bit: 324530 (4GB memory, 4GB swap file)
					// windows XP SP1 64bit: 2550445 (4GB memory, 4GB swap file)
					// vista 32:895257 (8GB memory, 4GB swap file)
					// vista >3.55 million (8GB memory, ??? GB swap file)
					// 7 32: 764274 (8GB memory, system swap file)
					// 8 32: 663377 (8GB memory, system swap file)
					// 8.1 32: 651039 (8GB memory, system swap file)
					// 10 32: 524637 (8GB memory, system swap file)
					// windows 2k3: 272253 (6GB memory, system picked swap)
					// windows 2k8 datacenter 32: 514542 (13.3GB memory, system picked swap)
					// TODO: windows 1.x, 2.x, 3.x, 64bit other then windows XP
					
					DWORD dwMinorVersion;
					DWORD dwMajorVersion;
					DWORD dwBuild;
					DWORD dwPlatformId;
					BYTE wProductType;
					BOOL zIsNt;
					BOOL zIsWin32s;
					WORD wProcessorArchitecture;

					GetWindowsInfo::GetWindowsVersion(dwMinorVersion, dwMajorVersion, dwBuild, dwPlatformId, wProductType, zIsNt, zIsWin32s, wProcessorArchitecture);
					
					switch(dwMajorVersion)
					{
						case 3:
							switch(dwMinorVersion)
							{
								case 0x0a:
									// WIN 3.11 (WIN32s)
									if(zIsWin32s)
									{
										retVal = 27;
									}
									// NT 3.1
									else
									{
										retVal = 4033;
									}
									break;
								// NT 3.5
								case 0x32:
									retVal = 30676;
									break;
								// NT 3.51
								case 0x33:
									retVal = 32403;
									break;
								default:
									retVal = -1;
									errno = EINVAL;
									break;
							}
							break;
						case 4:
							{
								switch(dwMinorVersion)
								{
									// WIN 95 and NT 4
									case 0:
										switch(dwPlatformId)
										{
											// NT 4
											case 2:
												retVal = 30069;
												break;
											// WIN 95
											default:
												retVal = 64967;
												break;
										}
										break;
									// WIN 98
									case 0x0a:
										retVal = 22527;
										break;
									// WIN ME
									case 0x5a:
										retVal = 20443;
										break;
									default:
										retVal = -1;
										errno = EINVAL;
								}
							}
							break;
						case 5:
							{
								switch(dwMinorVersion)
								{
									// WIN 20000
									case 0:
										retVal = 300832;
										break;
									// WIN XP
									case 1:
										retVal = 324530;
										break;
									// WIN XP 64 and 2003
									case 2:
										switch(wProductType)
										{
											case 1:
												// XP
												retVal = 2550445;
												break;
											default:
												// 2003
												switch(wProcessorArchitecture)
												{
													// x86
													case 0:
														retVal = 272253;
														break;
													// x64
													default:
														retVal = -1;
														errno = EINVAL;
														break;
												}
												break;
										}
										break;
								}
							}
							break;
						case 6:
							{
								switch(dwMinorVersion)
								{
									// Vista, 2008
									case 0:
										switch(wProductType)
										{
											case 1:
												// VISTA
												switch(wProcessorArchitecture)
												{
													// x86
													case 0:
														retVal = 895257;
														break;
													// x64
													default:
														retVal = -1;
														errno = EINVAL;
														break;
												}
												break;
											default:
												// 2008
												switch(wProcessorArchitecture)
												{
													// x86
													case 0:
														retVal = 514542;
														errno = EINVAL;
														break;
													// x64
													default:
														retVal = -1;
														errno = EINVAL;
														break;
												}
												break;
										}
										break;
									// 7, 2008 R2
									case 1:
										switch(wProductType)
										{
											case 1:
												// 7
												switch(wProcessorArchitecture)
												{
													// x86
													case 0:
														retVal = 764274;
														errno = EINVAL;
														break;
													// x64
													default:
														retVal = -1;
														errno = EINVAL;
														break;
												}
												break;
											default:
												// 2008 R2
												switch(wProcessorArchitecture)
												{
													// x86
													case 0:
														retVal = -1;
														errno = EINVAL;
														break;
													// x64
													default:
														retVal = -1;
														errno = EINVAL;
														break;
												}
												break;
										}
										break;
									// 8, 2012
									case 2:
										switch(wProductType)
										{
											case 1:
												// 8
												switch(wProcessorArchitecture)
												{
													// x86
													case 0:
														retVal = 663377;
														errno = EINVAL;
														break;
													// x64
													default:
														retVal = -1;
														errno = EINVAL;
														break;
												}
												break;
											default:
												// 2012
												switch(wProcessorArchitecture)
												{
													// x86
													case 0:
														retVal = -1;
														errno = EINVAL;
														break;
													// x64
													default:
														retVal = -1;
														errno = EINVAL;
														break;
												}
												break;
										}
										break;
									// 8.1, 2012 R2
									case 3:
										switch(wProductType)
										{
											case 1:
												// 8.1
												switch(wProcessorArchitecture)
												{
													// x86
													case 0:
														retVal = 651039;
														errno = EINVAL;
														break;
													// x64
													default:
														retVal = -1;
														errno = EINVAL;
														break;
												}
												break;
											default:
												// 2012 R2
												switch(wProcessorArchitecture)
												{
													// x86
													case 0:
														retVal = -1;
														errno = EINVAL;
														break;
													// x64
													default:
														retVal = -1;
														errno = EINVAL;
														break;
												}
												break;
										}
										break;
								}
							}
							break;
						case 10:
							{
								switch(dwMinorVersion)
								{
									// 10, 2016
									case 0:
										switch(wProductType)
										{
											case 1:
												// 10
												switch(wProcessorArchitecture)
												{
													// x86
													case 0:
														retVal = 524637;
														break;
													// x64
													default:
														retVal = -1;
														errno = EINVAL;
														break;
												}
												break;
											default:
												// 2016
												switch(wProcessorArchitecture)
												{
													// x86
													case 0:
														retVal = -1;
														errno = EINVAL;
														break;
													// x64
													default:
														retVal = -1;
														errno = EINVAL;
														break;
												}
												break;
										}
										break;
								}
							}
							break;
						default:
							retVal = -1;
							errno = EINVAL;
							break;
					}
				}
				break;
#if _SC_PAGESIZE != _SC_PAGE_SIZE
			case _SC_PAGESIZE:
#endif
			case _SC_PAGE_SIZE:
				PLSYSTEM_INFO pSystemInfo;
				GetWindowsInfo::GetWindowsSystemInfo(&pSystemInfo);
				retVal = pSystemInfo->dwPageSize;
				break;
			case _SC_RE_DUP_MAX:
				retVal = RE_DUP_MAX;
				break;
			case _SC_STREAM_MAX:
				#if defined(_MSC_VER)
					#if (_MSC_VER >= 1000)
						retVal = _getmaxstdio();
					#else
						retVal = 512;
					#endif
				#else
					retVal = _getmaxstdio();
				#endif
				break;
			case _SC_SYMLOOP_MAX:
				retVal = SYMLOOP_MAX;
				break;
			case _SC_TTY_NAME_MAX:
				{
					DWORD dwMinorVersion;
					DWORD dwMajorVersion;
					DWORD dwBuild;
					DWORD dwPlatformId;
					BYTE wProductType;
					BOOL zIsNt;
					BOOL zIsWin32s;
					WORD wProcessorArchitecture;

					GetWindowsInfo::GetWindowsVersion(dwMinorVersion, dwMajorVersion, dwBuild, dwPlatformId, wProductType, zIsNt, zIsWin32s, wProcessorArchitecture);
					
					if(dwMajorVersion >= 4)
						retVal = MAX_PATH;
					else
						retVal = 12;
				}
				break;
			case _SC_TZNAME_MAX:
				TIME_ZONE_INFORMATION tzInfo;
				retVal = MAX(sizeof tzInfo.StandardName / sizeof tzInfo.StandardName[0], sizeof tzInfo.DaylightName / sizeof tzInfo.DaylightName[0]) - 1;
				break;
			case _SC_VERSION:
				retVal = 198801L;
				break;
			case _SC_BC_BASE_MAX:
				retVal = 99; // shamelessly stolen from Linux as Windows doesn't have BC separate from GnuWin32 Project
				break;
			case _SC_BC_DIM_MAX:
				retVal = 2048; // shamelessly stolen from Linux as Windows doesn't have BC separate from GnuWin32 Project
				break;
			case _SC_BC_SCALE_MAX:
				retVal = 99; // shamelessly stolen from Linux as Windows doesn't have BC separate from GnuWin32 Project
				break;
			case _SC_BC_STRING_MAX:
				retVal = 1000; // shamelessly stolen from Linux as Windows doesn't have BC separate from GnuWin32 Project
				break;
			case _SC_COLL_WEIGHTS_MAX:
				retVal = COLL_WEIGHTS_MAX;
				break;
			case _SC_EXPR_NEST_MAX:
				retVal = 32; // shamelessly stolen from Linux as Windows doesn't have expr separate from GnuWin32 Project
				break;
			case _SC_LINE_MAX:
				{
					// 64 - 1 max < windows 2000
					// 1020 - 1 max = windows NT 3.51, NT 4.0 Workstation
					// 1024 - 1 max = windows 2000
					// 4096 - 1 >= windows XP
					//retVal = ARG_MAX;
					DWORD dwMinorVersion;
					DWORD dwMajorVersion;
					DWORD dwBuild;
					DWORD dwPlatformId;
					BYTE wProductType;
					BOOL zIsNt;
					BOOL zIsWin32s;
					WORD wProcessorArchitecture;

					GetWindowsInfo::GetWindowsVersion(dwMinorVersion, dwMajorVersion, dwBuild, dwPlatformId, wProductType, zIsNt, zIsWin32s, wProcessorArchitecture);

					// Win 3.11
					if(dwMajorVersion == 3 && dwMinorVersion == 0x0a && zIsWin32s)
					{
						retVal = 126;
					}
					// NT 3.1 and NT 3.5
					else if(dwMajorVersion == 3 && (dwMinorVersion == 0x0a || dwMinorVersion == 0x32))
					{
						retVal = 1023;
					}
					// NT 3.51, NT 4.0, and Windows 2000
					else if((dwMajorVersion == 3 && dwMinorVersion == 0x33) || (dwMajorVersion == 4 && dwMinorVersion == 0 && dwPlatformId == 2) || (dwMajorVersion == 5 && dwMinorVersion == 0))
					{
						retVal = 2047;
					}
					// Win 9x
					else if(dwMajorVersion < 5)
					{
						retVal = 126;
					}
					else
					{
						retVal = 8191;
					}
				}
				break;
			case _SC_2_VERSION:
				retVal = 198801L;
				break;
			case _SC_2_C_DEV:
				retVal = 0L;
				break;
			case _SC_2_FORT_DEV:
				retVal = 0L;
				break;
			case _SC_2_FORT_RUN:
				retVal = 0L;
				break;
			case _SC_2_LOCALEDEF:
				retVal = 0L;
				break;
			case _SC_2_SW_DEV:
				retVal = 0L;
				break;
			case _SC_PHYS_PAGES:
				{
					DWORDLONG res;
					LMEMORYSTATUSEX status;
					PLSYSTEM_INFO pSystemInfo;
				
					GetWindowsInfo::GetPhysicalMemory(&status);
					GetWindowsInfo::GetWindowsSystemInfo(&pSystemInfo);
					
					res = ((status.ullTotalPhys + (pSystemInfo->dwPageSize - 1)) / pSystemInfo->dwPageSize);
					//res = (status.ullTotalPhys / pSystemInfo->dwPageSize) + (status.ullTotalPhys % pSystemInfo->dwPageSize != 0);
					retVal = (res > LONG_MAX) ? LONG_MAX : (long)res;
				}
				break;
			case _SC_AVPHYS_PAGES:
				{
					DWORDLONG res;
					LMEMORYSTATUSEX status;
					PLSYSTEM_INFO pSystemInfo;
				
					GetWindowsInfo::GetPhysicalMemory(&status);
					GetWindowsInfo::GetWindowsSystemInfo(&pSystemInfo);
					
					res = ((status.ullAvailPhys + (pSystemInfo->dwPageSize - 1)) / pSystemInfo->dwPageSize);
					//res = (status.ullAvailPhys / pSystemInfo->dwPageSize) + (status.ullAvailPhys % pSystemInfo->dwPageSize != 0);
					retVal = (res > LONG_MAX) ? LONG_MAX : (long)res;
				}
				break;
			case _SC_NPROCESSORS_CONF:
				{
					PLSYSTEM_INFO pSystemInfo;

					GetWindowsInfo::GetWindowsSystemInfo(&pSystemInfo);
					
					retVal = pSystemInfo->dwNumberOfProcessors;
				}
				break;
			case _SC_NPROCESSORS_ONLN:
				{
					PLSYSTEM_INFO pSystemInfo;

					GetWindowsInfo::GetWindowsSystemInfo(&pSystemInfo);
					
					retVal = dWordnumberOfSetBits(pSystemInfo->dwActiveProcessorMask);
				}
				break;
			default:
				retVal = -1;
				errno = EINVAL;
				break;
        }

        return retVal;
}

#include <stdio.h>

#define SYSCONFCALL(A) \
	sysconfOut = sysconf(A); \
	fprintf(stdout, #A ": %lu\n", sysconfOut);
	
int main(void)
{
					DWORD dwMinorVersion;
					DWORD dwMajorVersion;
					DWORD dwBuild;
					DWORD dwPlatformId;
					BYTE wProductType;
					BOOL zIsNt;
					BOOL zIsWin32s;
					WORD wProcessorArchitecture;
					long sysconfOut;

					GetWindowsInfo::GetWindowsVersion(dwMinorVersion, dwMajorVersion, dwBuild, dwPlatformId, wProductType, zIsNt, zIsWin32s, wProcessorArchitecture);
					
					fprintf(stdout, "Windows Version: major: 0x%04lx, minor: 0x%04lx, build: 0x%04lx,\n"
								"\tplatform ID: 0x%04lx, productType: 0x%02lx\n"
								"\tis NT: %s, is win32s: %s, processor Architecture: 0x%04lx\n", 
								(unsigned long)dwMajorVersion, 
								(unsigned long)dwMinorVersion, 
								(unsigned long)dwBuild, 
								(unsigned long)dwPlatformId, 
								(unsigned long)wProductType,
								((zIsNt) ? "true" : "false"),
								((zIsWin32s) ? "true" : "false"),
								(unsigned long)wProcessorArchitecture);
					
					SYSCONFCALL(_SC_ARG_MAX);
					SYSCONFCALL(_SC_CHILD_MAX);
					SYSCONFCALL(_SC_HOST_NAME_MAX);
					SYSCONFCALL(_SC_LOGIN_NAME_MAX);
					SYSCONFCALL(_SC_NGROUPS_MAX);
					SYSCONFCALL(_SC_CLK_TCK);
					SYSCONFCALL(_SC_OPEN_MAX);
					SYSCONFCALL(_SC_PAGESIZE);
					SYSCONFCALL(_SC_PAGE_SIZE);
					SYSCONFCALL(_SC_RE_DUP_MAX);
					SYSCONFCALL(_SC_STREAM_MAX);
					SYSCONFCALL(_SC_SYMLOOP_MAX);
					SYSCONFCALL(_SC_TTY_NAME_MAX);
					SYSCONFCALL(_SC_TZNAME_MAX);
					SYSCONFCALL(_SC_VERSION);
					SYSCONFCALL(_SC_BC_BASE_MAX);
					SYSCONFCALL(_SC_BC_DIM_MAX);
					SYSCONFCALL(_SC_BC_SCALE_MAX);
					SYSCONFCALL(_SC_BC_STRING_MAX);
					SYSCONFCALL(_SC_COLL_WEIGHTS_MAX);
					SYSCONFCALL(_SC_EXPR_NEST_MAX);
					SYSCONFCALL(_SC_LINE_MAX);
					SYSCONFCALL(_SC_RE_DUP_MAX);
					SYSCONFCALL(_SC_2_VERSION);
					SYSCONFCALL(_SC_2_C_DEV);
					SYSCONFCALL(_SC_2_FORT_DEV);
					SYSCONFCALL(_SC_2_FORT_RUN);
					SYSCONFCALL(_SC_2_LOCALEDEF);
					SYSCONFCALL(_SC_2_SW_DEV);
					SYSCONFCALL(_SC_PHYS_PAGES);
					SYSCONFCALL(_SC_AVPHYS_PAGES);
					SYSCONFCALL(_SC_NPROCESSORS_CONF);
					SYSCONFCALL(_SC_NPROCESSORS_ONLN);

	return 0;
}
