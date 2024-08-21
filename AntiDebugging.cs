using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ArtemisSecurity
{
    public static class AntiDebugging
    {
        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();

        public static void PreventDebugging()
        {
            if (IsDebuggerPresent() || Debugger.IsAttached)
            {
                Console.WriteLine("Debugger detected! Terminating...");
                Environment.Exit(-1);
            }
        }
    }

    public static class AntiTampering
    {
        public static void ValidateIntegrity()
        {
            var currentHash = GetApplicationHash();
            // Compare with a known good hash
            if (currentHash != "KnownGoodHash")
            {
                Console.WriteLine("Application tampered with! Terminating...");
                Environment.Exit(-1);
            }
        }

        private static string GetApplicationHash()
        {
            // Implement your hashing logic to check integrity
            return "ApplicationHash";
        }
    }
}
