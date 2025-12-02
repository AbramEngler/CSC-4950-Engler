using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using EDRSensor.Logging;
using Microsoft.Extensions.Logging;

namespace EDRSensor.Modules
{
    public class DetectionEngine
    {
        private readonly Dictionary<int, List<DateTime>> _keystrokePacketTimes = new();
        private readonly Dictionary<int, List<int>> _smallPacketSizes = new();
        private readonly List<WindowChangeEvent> _windowEvents = new();
        private readonly Dictionary<int, List<DateTime>> _windowChangeTimes = new();

        private readonly int _packetThreshold = 3; //3 small packets
        private readonly int _timeWindowMs = 3000; //within 1 seconds

        private readonly TimeSpan WindowCorrelationThreshold = TimeSpan.FromMilliseconds(500); //window switch time threshold


        public void IngestNetworkEvent(NetworkEventData nevt)
        {
            //Track small outbound packets
            if (nevt.Size <= 1)
            {
                if (!_keystrokePacketTimes.ContainsKey(nevt.ProcessID))
                    _keystrokePacketTimes[nevt.ProcessID] = new List<DateTime>();

                _keystrokePacketTimes[nevt.ProcessID].Add(nevt.TimeStamp);

                RunKeyloggerDetection(nevt.ProcessID);
            }

            RunWindowCorrelation(nevt);

        }

        public void IngestProcessEvent(ProcessEventData evt)
        {
            if (evt.EventType == "WindowChange")
            {
                if (!_windowChangeTimes.ContainsKey(evt.ProcessID))
                    _windowChangeTimes[evt.ProcessID] = new List<DateTime>();

                _windowChangeTimes[evt.ProcessID].Add(evt.TimeStamp);
            }
        }

        public void IngestWindowEvent(WindowChangeEvent wevt)
        {
            if (_windowEvents.Count > 0)
            {
                var last = _windowEvents.Last();
                if ((wevt.TimeStamp - last.TimeStamp).TotalMilliseconds < 300)
                    return; //ignore duplicate burst
            }

            _windowEvents.Add(wevt);

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[WINDOW EVENT] {wevt.WindowTitle} PID {wevt.ProcessId}");
            Console.ResetColor();
        }

        private void RunWindowCorrelation(NetworkEventData nevt)
        {
            //if there are no window events
            if (_windowEvents.Count == 0) return;
            
            var proc = Process.GetProcessById(nevt.ProcessID);


            //find the most recent window change that occurred before this network event
            var candidate = _windowEvents
                .Where(w => w.TimeStamp <= nevt.TimeStamp)  //only prior or equal
                .OrderByDescending(w => w.TimeStamp)
                .FirstOrDefault();

            if (candidate == null) return;

            //must be recent enough and owned by same process
            var delta = nevt.TimeStamp - candidate.TimeStamp;
            if (delta <= WindowCorrelationThreshold && nevt.Size > 20)
            {
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine($"[ALERT] Window switch + outbound packet detected from PID {nevt.ProcessID}\nApplication: {proc.ProcessName}");
                SensorLogger.LogAlert($"[ALERT] Window switch + outbound packet detected from PID {nevt.ProcessID}\nApplication: {proc.ProcessName}");
                Console.ResetColor();
            }
        }

        private void RunKeyloggerDetection(int pid)
        {
            var timestamps = _keystrokePacketTimes[pid];

            DateTime now = DateTime.Now;
            timestamps.RemoveAll(t => (now - t).TotalMilliseconds > _timeWindowMs);

            var proc = Process.GetProcessById(pid);


            if (timestamps.Count >= _packetThreshold && pid != 2832 && pid != 1860 && pid != 24228 && pid != 27328 && pid != 16740 && pid != 2288)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[ALERT] Possible keylogger behavior detected in PID {pid} \n Application: {proc.ProcessName}");
                SensorLogger.LogAlert($"[ALERT] Possible keylogger behavior detected in PID {pid} \n Application: {proc.ProcessName}");
                Console.ResetColor();
            }
        }
    }
}
