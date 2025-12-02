using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace EDRSensor.Modules
{
    public class WindowChangeEvent
    {
        public DateTime TimeStamp { get; set; }
        public string WindowTitle { get; set; }
        public int ProcessId { get; set; }
    }

    public class WindowSensor
    {
        private delegate void WinEventDelegate(
            IntPtr hWinEventHook,
            uint eventType,
            IntPtr hwnd,
            int idObject,
            int idChild,
            uint dwEventThread,
            uint dwmsEventTime);

        private WinEventDelegate _callback;
        private IntPtr _hook;

        private readonly Action<WindowChangeEvent> _onEvent;

        public WindowSensor(Action<WindowChangeEvent> callback)
        {
            _onEvent = callback;
        }

        public void Start()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("[DEBUG] WindowSensor.Start() called");
            Console.ResetColor();

            _callback = WinEventProc;

            _hook = SetWinEventHook(
                EVENT_SYSTEM_FOREGROUND,
                EVENT_SYSTEM_FOREGROUND,
                IntPtr.Zero,
                _callback,
                0,
                0,
                WINEVENT_OUTOFCONTEXT);

            Console.WriteLine("[WindowSensor] Listening for active window changes...");
        }

        private void WinEventProc(
            IntPtr hWinEventHook,
            uint eventType,
            IntPtr hwnd,
            int idObject,
            int idChild,
            uint dwEventThread,
            uint dwmsEventTime)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[DEBUG] WinEventProc fired");
            Console.ResetColor();

            if (hwnd == IntPtr.Zero) return;

            GetWindowThreadProcessId(hwnd, out uint pid);

            var title = Process.GetProcessById((int)pid).ProcessName;

            _onEvent(new WindowChangeEvent
            {
                TimeStamp = DateTime.Now,
                WindowTitle = title,
                ProcessId = (int)pid
            });
        }

        private static string GetWindowText(IntPtr hwnd)
        {
            for (int i = 0; i < 5; i++)
            {
                int length = GetWindowTextLength(hwnd);
                if (length > 0)
                {
                    StringBuilder sb = new StringBuilder(length + 1);
                    GetWindowText(hwnd, sb, sb.Capacity);
                    return sb.ToString();
                }
                Thread.Sleep(50);
            }
            return "(No Title)";
        }

        public void Stop()
        {
            UnhookWinEvent(_hook);
        }

        const uint EVENT_SYSTEM_FOREGROUND = 0x0003;
        const uint WINEVENT_OUTOFCONTEXT = 0;

        [DllImport("user32.dll")]
        static extern IntPtr SetWinEventHook(
            uint eventMin,
            uint eventMax,
            IntPtr hmodWinEventProc,
            WinEventDelegate lpfnWinEventProc,
            uint idProcess,
            uint idThread,
            uint dwFlags);

        [DllImport("user32.dll")]
        static extern bool UnhookWinEvent(IntPtr hWinEventHook);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll")]
        static extern int GetWindowTextLength(IntPtr hWnd);
    }
}