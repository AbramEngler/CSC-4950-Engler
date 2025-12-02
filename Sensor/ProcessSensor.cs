using System;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace EDRSensor.Modules
{

    public class ProcessEventData
    {
        public string EventType { get; set; }
        public DateTime TimeStamp { get; set; }
        public int ProcessID { get; set; }
        public int ParentProcessID { get; set; }
        public string ImagePath { get; set; }
        public string CommandLine { get; set; }
        public int SessionID { get; set; }
        public long ImageSize { get; set; }
    }
    
    public class ProcessSensor
    {
        private TraceEventSession _session;
        private readonly Action<ProcessEventData> _onEvent;

        public ProcessSensor(Action<ProcessEventData> eventCallback)
        {
            _onEvent = eventCallback;
        }

        public void Start()
        {
            Console.WriteLine("[ProcessSensor] Starting...");

            //Use a realtime session
            _session = new TraceEventSession("ProcessSensorSession");
            _session.StopOnDispose = true;

            //Enable Kernel Process Events
            _session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.ImageLoad
            );

            //Process start
            _session.Source.Kernel.ProcessStart += data =>
            {
                var evt = new ProcessEventData
                {
                    EventType = "ProcessStart",
                    TimeStamp = data.TimeStamp,
                    ProcessID = data.ProcessID,
                    ParentProcessID = data.ParentID,
                    ImagePath = data.ImageFileName,
                    CommandLine = data.CommandLine,
                    SessionID = data.SessionID
                };

                _onEvent(evt);
            };

            //Process end
            _session.Source.Kernel.ProcessStop += data =>
            {
                var evt = new ProcessEventData
                {
                    EventType = "ProcessStop",
                    TimeStamp = data.TimeStamp,
                    ProcessID = data.ProcessID,
                    ParentProcessID = data.ParentID,
                    ImagePath = data.ImageFileName,
                };

                _onEvent(evt);
            };

            //DLL loads
            _session.Source.Kernel.ImageLoad += data =>
            {
                var evt = new ProcessEventData
                {
                    EventType = "DllLoad",
                    TimeStamp = data.TimeStamp,
                    ProcessID = data.ProcessID,
                    ImagePath = data.FileName,
                    ImageSize = data.ImageSize
                };

                _onEvent(evt);
            };

            //Start ETW processing on background thread
            Task.Run(() => _session.Source.Process());
        }

        public void Stop()
        {
            _session?.Dispose();
        }
    }

    
}