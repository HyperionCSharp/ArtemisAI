using System;
using System.Management;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace ArtemisSecurity
{
    public static class AntiEmulatorVM
    {
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsDebuggerPresent();

        public static void DetectEmulatorOrVM()
        {
            if (IsRunningInVM() || IsRunningInEmulator() || IsDebuggerAttached())
            {
                Console.WriteLine("VM, Emulator, or Debugger detected! Terminating...");
                Environment.Exit(-1);
            }
        }

        private static bool IsRunningInVM()
        {
            using (var searcher = new ManagementObjectSearcher("Select * from Win32_ComputerSystem"))
            {
                foreach (var item in searcher.Get())
                {
                    string manufacturer = item["Manufacturer"].ToString().ToLower();
                    string model = item["Model"].ToString().ToUpperInvariant();

                    if ((manufacturer == "microsoft corporation" && model.Contains("VIRTUAL")) ||
                        manufacturer.Contains("vmware") ||
                        manufacturer.Contains("xen") ||
                        manufacturer.Contains("virtualbox") ||
                        manufacturer.Contains("qemu"))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        private static bool IsRunningInEmulator()
        {
            // Check for common emulator-specific environment variables
            string[] emulatorEnvVars = { "ANDROID_EMULATOR_HYPERVISOR", "QEMU_AUDIO_DRV", "QEMU" };
            foreach (var envVar in emulatorEnvVars)
            {
                if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable(envVar)))
                {
                    return true;
                }
            }

            // Check for emulator-specific processes
            string[] emulatorProcesses = { "qemu-system", "windroy", "nox" };
            foreach (var processName in emulatorProcesses)
            {
                if (Process.GetProcessesByName(processName).Length > 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool IsDebuggerAttached()
        {
            return IsDebuggerPresent() || Debugger.IsAttached;
        }
    }
}
