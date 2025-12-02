using System;
using System.IO;

namespace EDRSensor.Logging
{
    public class SensorLogger
    {
        private static object _lock = new();
        private static string ScanLogFilePath;

        public static void Initialize()
        {
            string ScanLogDir = "C:\\Users\\abram\\Desktop\\Capstone\\KeyloggerScanLogs";

            string timestamp = DateTime.Now.ToString("yyyy-MM-dd_HH.mm.ss");

            ScanLogFilePath = Path.Combine(ScanLogDir, $"EDR_Log_{timestamp}.txt");

            LogAlert($"=== EDR Scan Started at {DateTime.Now} === \n\n");
        }

        public static void LogAlert(string message)
        {
            lock (_lock)
            {
                File.AppendAllText(ScanLogFilePath,
                    $"{DateTime.Now:HH:mm:ss}  {message}\n\n");
            }
        }
    }
}