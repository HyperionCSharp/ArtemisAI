using System;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace ArtemisSecurity
{
    public static class ProcessMonitor
    {
        [DllImport("user32.dll")]
        private static extern int GetWIndowTextLength(IntPtr hWnd);
        [DllImport("user32.dll")]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
        private static readonly List<Regex> BlacklistedProcessPatterns = new List<Regex>
        {
            new Regex(@"dnspy|ida|ida64|idag|idag64|idaw|idaw64|idaq|idaq64|idau|idau64", RegexOptions.IgnoreCase),
            new Regex(@"ollydbg|x64dbg|x32dbg|windbg|IMMUNITYDEBUGGER", RegexOptions.IgnoreCase),
            new Regex(@"wireshark|fiddler|charles|burpsuite", RegexOptions.IgnoreCase),
            new Regex(@"javaw|radare2|binary ninja|hopper", RegexOptions.IgnoreCase),
            new Regex(@"ilspy|dotpeek|justdecompile|reflector", RegexOptions.IgnoreCase),
            new Regex(@"de4dot|simplify|deobfuscator", RegexOptions.IgnoreCase)
        };

        public static List<string> GetSimilarWindowTitles(string processName)
        {
            var similarWindows = new List<string>();
            Process[] processes = Process.GetProcessesByName(processName);

            foreach (Process process in processes)
            {
                IntPtr mainWindowHandle = process.MainWindowHandle;
                if (mainWindowHandle != IntPtr.Zero)
                {
                    int textLength = GetWIndowTextLength(mainWindowHandle);
                    StringBuilder windowTitle = new StringBuilder(textLength + 1);
                    GetWindowText(mainWindowHandle, windowTitle, windowTitle.Capacity);
                    similarWindows.Add(windowTitle.ToString());
                }
            }
            return similarWindows;
        }

        private static readonly List<string> WhitelistedProcesses = new List<string>
        {
            "explorer", "svchost", "csrss", "winlogon"
        };

        public static bool DetectBlacklistedProcesses(ThreatAnalyzer threatAnalyzer, List<(string Name, float Level)> detectedThreats)
        {
            var runningProcesses = Process.GetProcesses();
            bool detected = false;

            foreach (var process in runningProcesses)
            {
                if (WhitelistedProcesses.Contains(process.ProcessName, StringComparer.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (BlacklistedProcessPatterns.Any(pattern => pattern.IsMatch(process.ProcessName)))
                {
                    Console.WriteLine($"Unauthorized process detected: {process.ProcessName}");

                    float threatLevel = CalculateThreatLevel(process);
                    detectedThreats.Add((process.ProcessName, threatLevel));

                    // Log and analyze the detected threat
                    threatAnalyzer.LogAndAnalyzeThreat(process.ProcessName, threatLevel);
            
                    MonitorProcessDetails(process);
                    detected = true;
                }
            }
            return detected;
        }


        private static void MonitorProcessDetails(Process process)
        {
            Console.WriteLine($"Process ID: {process.Id}");
            Console.WriteLine($"Memory Usage: {process.WorkingSet64 / 1024 / 1024} MB");
            Console.WriteLine($"CPU Time: {process.TotalProcessorTime}");
            
            try
            {
                Console.WriteLine($"Start Time: {process.StartTime}");
            }
            catch (Exception)
            {
                Console.WriteLine("Start Time: Unable to retrieve");
            }

            // Attempt to block IPC
            try
            {
                process.PriorityClass = ProcessPriorityClass.Idle;
                Console.WriteLine("Process priority set to Idle");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to modify process priority: {ex.Message}");
            }
        }

        private static float CalculateThreatLevel(Process process)
        {
            string processName = process.ProcessName.ToLower();

            var threatLevels = new Dictionary<string, float>
            {
                {"debugger", 1.0f},
                {"sniffer", 1.0f},
                {"backdoor", 1.0f},
                {"deobfuscator", 1.0f},
                {"decompiler", 1.0f},
                {"emulator", 1.0f},
                {"disassembler", 1.0f},
                {"injector", 0.5f},
                {"rootkit", 1.0f},
                {"keylogger", 0.7f},
                {"trojan", 0.5f},
                {"adware", 0.3f},
                {"spyware", 0.2f},
                {"ransomware", 0.5f},
                {"phishingtool", 1.0f},
                {"cryptominer", 0.3f},
                {"remoteaccesstool", 0.7f},
                {"packetanalyzer", 0.8f},
                {"fakeantivirus", 0.4f}
            };

            foreach (var threat in threatLevels)
            {
                if (processName.Contains(threat.Key))
                {
                    return threat.Value;
                }
            }

            return 0.1f;
        }
    }
}