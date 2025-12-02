using System;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace EDRSensor.Modules
{
    public class NetworkEventData
    {
        public string EventType { get; set; }
        public DateTime TimeStamp { get; set; }
        public int ProcessID { get; set; }
        public int Size { get; set; }
        public string SourceIP { get; set; }
        public string DestIP { get; set; }
        public int SourcePort { get; set; }
        public int DestPort { get; set; }
    }

    public class NetworkSensor
    {
        private TraceEventSession _session;
        private readonly Action<NetworkEventData> _onNetworkEvent;

        public NetworkSensor(Action<NetworkEventData> callback)
        {
            _onNetworkEvent = callback;
        }

        public void Start()
        {
            Console.WriteLine("[NetworkSensor] Starting...");

            _session = new TraceEventSession("NetworkSensorKernelSession");
            _session.StopOnDispose = true;

            //Enable kernel provider
            _session.EnableKernelProvider
            (
                KernelTraceEventParser.Keywords.NetworkTCPIP
            );

            var source = _session.Source;

            //TCP Send
            source.Kernel.TcpIpSend += data =>
            {
                var nevt = new NetworkEventData
                {
                    EventType = "TcpSend",
                    TimeStamp = data.TimeStamp,
                    ProcessID = data.ProcessID,
                    Size = data.size,
                    SourceIP = data.saddr.ToString(),
                    DestIP = data.daddr.ToString(),
                    SourcePort = data.sport,
                    DestPort = data.dport
                };

                _onNetworkEvent(nevt);
            };

            //TCP Receive
            source.Kernel.TcpIpRecv += data =>
            {
                var nevt = new NetworkEventData
                {
                    EventType = "TcpRecv",
                    TimeStamp = data.TimeStamp,
                    ProcessID = data.ProcessID,
                    Size = data.size,
                    SourceIP = data.saddr.ToString(),
                    DestIP = data.daddr.ToString(),
                    SourcePort = data.sport,
                    DestPort = data.dport
                };

                _onNetworkEvent(nevt);
            };

            Task.Run(() =>
            {
                while (true)
                {
                    try
                    {
                        source.Process();
                    }
                    catch (Exception ex)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("[NetworkSensor] ETW CRASHED: " + ex.Message);
                        Console.WriteLine("[NetworkSensor] Restarting...");
                        Console.ResetColor();
                    }

                    Thread.Sleep(1000);
                }
            });
        }

        public void Stop()
        {
            _session?.Dispose();
        }
    }
}