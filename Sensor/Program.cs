using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using EDRSensor.Logging;
using EDRSensor.Modules;

namespace DefenderSensor
{
    internal class Program
    {
        
        private static CancellationTokenSource _cts;

        static async Task Main(string[] args)
        {
            Console.Title = "Spyware Sensor – Process, Network, Window ETW";

            Console.WriteLine("=== Defender Sensor Started ===");
            Console.WriteLine("Listening for process creation/temination, network activity, suspicious window behavior.");

            SensorLogger.Initialize();

            //exit with Ctrl C
            _cts = new CancellationTokenSource();
            Console.CancelKeyPress += (s, e) =>
            {
                Console.WriteLine("\nStopping ETW session...");
                e.Cancel = true;
                _cts.Cancel();
            };

            //Callback from process ETW events
            Action<ProcessEventData> onProcessEvent = evt =>
            {
                PrintProcessEvent(evt);
            };

            Action<NetworkEventData> onNetworkEvent = nevt =>
            {
                PrintNetworkEvent(nevt);
            };

            //Start ETW Sensors                
            var detection = new DetectionEngine(); 
            var processSensor = new ProcessSensor(evt =>
            {
                detection.IngestProcessEvent(evt);
                PrintProcessEvent(evt);
            });

            var networkSensor = new NetworkSensor(nevt =>
            {
                detection.IngestNetworkEvent(nevt);
                PrintNetworkEvent(nevt);
            });

            var windowSensor = new WindowSensor(wevt =>
            {
                detection.IngestWindowEvent(wevt);
            });

            // _processSensor = new ProcessSensor(onProcessEvent);
            // _processSensor.Start();

            // _networkSensor = new NetworkSensor(onNetworkEvent);
            // _networkSensor.Start();

            processSensor.Start();
            networkSensor.Start();
            windowSensor.Start();

            RunMessageLoop();

            // Keep console alive until Ctrl+C
            while (!_cts.Token.IsCancellationRequested)
            {
                Thread.Sleep(500);
            }

            Console.WriteLine("\nETW session closed. Exiting program.");
        }

        private static void PrintProcessEvent(ProcessEventData evt)
        {
            switch (evt.EventType)
            {
                case "ProcessStart":
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"[START] PID {evt.ProcessID}  Parent {evt.ParentProcessID}");
                    Console.WriteLine($"        {evt.ImagePath}");
                    if (!string.IsNullOrEmpty(evt.CommandLine))
                        Console.WriteLine($"        CMD: {evt.CommandLine}");
                    break;

                case "ProcessStop":
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[STOP]  PID {evt.ProcessID}");
                    Console.WriteLine($"        {evt.ImagePath}");
                    break;

                case "ImageLoad":
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"[MODULE] PID {evt.ProcessID} → Loaded {evt.ImagePath}");
                    break;
            }

            Console.ResetColor();
        }


        private static void PrintNetworkEvent(NetworkEventData nevt)
        {
            string image = Process.GetProcessById(nevt.ProcessID).ProcessName.ToLower();

            switch (nevt.EventType)
            {
                case "TcpSend":
                    // if (nevt.DestPort != 5000)
                    // {
                    //     return;
                    // }

                    //Filter out some common noisy processes 
                    if (image == "svchost" ||
                        image == "idle" ||
                        image == "lsass" ||
                        image == "wininit" ||
                        image == "services" ||
                        image == "wudfhost" || //this especially causes a lot of noise
                        nevt.ProcessID == 2832 ||
                        nevt.ProcessID == 1860 ||
                        image == "zoom" ||
                        image == "cpthost" ||
                        image == "aomhost64" ||
                        image == "system")
                    {
                        return;
                    }

                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine($"[NET] {nevt.TimeStamp} PID {nevt.ProcessID} SEND {nevt.Size} bytes → {nevt.DestIP}:{nevt.DestPort}");
                    break;

                case "TcpRecv":
                    // if (nevt.SourcePort != 5000)
                    // {
                    //     return;
                    // }

                    if (image == "svchost" ||
                        image == "idle" ||
                        image == "lsass" ||
                        image == "wininit" ||
                        image == "services" ||
                        image == "wudfhost" ||
                        nevt.ProcessID == 2832 ||
                        nevt.ProcessID == 1860 ||
                        image == "zoom" ||
                        image == "cpthost" ||
                        image == "aomhost64" ||
                        image == "system")
                    {
                        return;
                    }

                    Console.ForegroundColor = ConsoleColor.DarkCyan;
                    Console.WriteLine($"[NET] {nevt.TimeStamp} PID {nevt.ProcessID} RECV {nevt.Size} bytes ← {nevt.SourceIP}:{nevt.SourcePort}");
                    break;
            }

            Console.ResetColor();
        }

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        private struct MSG
        {
            public IntPtr hwnd;
            public uint message;
            public IntPtr wParam;
            public IntPtr lParam;
            public uint time;
            public System.Drawing.Point pt;
        }

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern bool GetMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern bool TranslateMessage(ref MSG lpMsg);

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern IntPtr DispatchMessage(ref MSG lpMsg);

        private static void RunMessageLoop()
        {
            Console.WriteLine("[DEBUG] Native Windows message loop active.");

            while (GetMessage(out MSG msg, IntPtr.Zero, 0, 0))
            {
                TranslateMessage(ref msg);
                DispatchMessage(ref msg);
            }
        }
    }
}