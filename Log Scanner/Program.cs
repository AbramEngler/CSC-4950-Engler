using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Text;

class Program
{
    //Sensitive Paterns
    static readonly Regex EmailRx = new(@"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", RegexOptions.Compiled);
    static readonly Regex GenericCardRx = new(@"\b(?:\d[ -]*?){13,19}\b", RegexOptions.Compiled);
    static readonly Regex CvvRx = new(@"\b(?<!\d)\d{3,4}(?!\d)\b", RegexOptions.Compiled);
    static readonly Regex SsnRx = new(@"\b\d{3}-\d{2}-\d{4}\b", RegexOptions.Compiled);
    static readonly Regex PasswordLikeRx = new(@"(?i)(password|pwd|pass)\s*[:=]\s*[^ \r\n]{4,}", RegexOptions.Compiled);

    //Window classifiers
    static readonly string[] SensitiveWindowKeywords = new[]
    {
        "login", "sign in", "sign-in", "log in", "logon", "signin",
        "checkout", "checkout -", "payment", "pay", "card", "credit", "cvv",
        "bank", "online banking", "account -", "secure checkout", "billing",
        "paypal", "stripe", "authorize.net", "amazon pay", "sign up", "sign-up",
        "register", "registration", "authorize", "discord", "steam"
    };

    //Banking names
    static readonly string[] BankNames = new[]
    {
        "chase", "bank of america", "wells fargo", "citi", "us bank", "capital one"
    };

    const int DefaultScanWindowLines = 1000;

    //Disctionary of sensitive windows to list
    static readonly Dictionary<string, List<int>> SensitiveWindowsSeen = new(StringComparer.OrdinalIgnoreCase);
    

    static void Main(string[] args)
    {

        var path = "C:\\Users\\abram\\Desktop\\Capstone\\KeyloggerLogs";
        var files = new List<string>();
        if (Directory.Exists(path))
        {
            files.AddRange(Directory.GetFiles(path, "*.log", SearchOption.TopDirectoryOnly));
        }

        else if (File.Exists(path))
        {
            files.Add(path);
        }

        else
        {
            Console.WriteLine($"Path not found: {path}");
            return;
        }

        foreach (var f in files)
        {
            Console.WriteLine($"\nScanning {Path.GetFileName(f)} ...");
            var alerts = ScanLogWithWindows(f);

            Console.WriteLine("\nSensitive windows seen:");
            if (SensitiveWindowsSeen.Count == 0)
            {
                Console.WriteLine("  None");
            }
            else
            {
                foreach (var kvp in SensitiveWindowsSeen)
                {
                    string title = kvp.Key;
                    string lines = string.Join(", ", kvp.Value);
                    Console.WriteLine($"  - \"{title}\" on lines: {lines}");
                }
            }

            if (alerts.Count == 0)
                Console.WriteLine("  No sensitive matches found.");
            else
            {
                Console.WriteLine($"\n  {alerts.Count} matches found:");
                foreach (var a in alerts)
                    Console.WriteLine("   - " + a.ToString());
            }


        }
    }

    //Detection record
    record Detection(string FilePath, string Type, string Matched, int LineNumber, string WindowTitle)
    {
        public override string ToString() => $"{Type} in window \"{WindowTitle}\" @line {LineNumber}: \"{Truncate(Matched, 60)}\"";
        static string Truncate(string s, int n) => s.Length <= n ? s : s.Substring(0, n - 3) + "...";
    }

    //Reads the log file, tracks active window titles
    static List<Detection> ScanLogWithWindows(string filePath)
    {
        var detections = new List<Detection>();
        var lines = File.ReadAllLines(filePath);

        string currentWindow = null;
        int currentWindowLine = -1;
        bool currentWindowSensitive = false;

        for (int i = 0; i < lines.Length; i++)
        {
            string line = lines[i];

            //Detect window changes
            if (line.Contains("New Active Window:"))
            {
                //extract title
                int idx = line.IndexOf("New Active Window:", StringComparison.OrdinalIgnoreCase);
                string title = line.Substring(idx + "New Active Window:".Length).Trim();
                title = title.Trim(new char[] { '[', ']', ' ' });
                currentWindow = title;
                currentWindowLine = i + 1; 

                //classify window by keywords and bank names
                currentWindowSensitive = IsWindowSensitive(title);

                //Record the sensitive window and the line number
                if (currentWindowSensitive)
                {
                    if (!SensitiveWindowsSeen.TryGetValue(title, out var linesList))
                    {
                        linesList = new List<int>();
                        SensitiveWindowsSeen[title] = linesList;
                    }
                    linesList.Add(currentWindowLine);
                }

                continue;
            }

            //Apply sensitive scanning
            if (currentWindowSensitive)
            {
            
                //Check email
                foreach (Match m in EmailRx.Matches(line))
                    detections.Add(new Detection(filePath, "Email", m.Value, i + 1, currentWindow));

                //Check SSN
                foreach (Match m in SsnRx.Matches(line))
                    detections.Add(new Detection(filePath, "SSN", m.Value, i + 1, currentWindow));

                //Check CVV
                foreach (Match m in CvvRx.Matches(line))
                {
                    string low = line.ToLowerInvariant();
                    if (low.Contains("cvv") || low.Contains("cvc") || low.Contains("security code") || low.Contains("card") || low.Contains("payment"))
                        detections.Add(new Detection(filePath, "CVV", m.Value, i + 1, currentWindow));
                }

                //Check possible credit cards
                foreach (Match m in GenericCardRx.Matches(line))
                {
                    var digitsOnly = Regex.Replace(m.Value, @"[^\d]", "");
                    if (digitsOnly.Length >= 13 && digitsOnly.Length <= 19)
                    {
                        if (IsLuhnValid(digitsOnly))
                            detections.Add(new Detection(filePath, "CreditCard", digitsOnly, i + 1, currentWindow));
                        else
                            detections.Add(new Detection(filePath, "PossibleCard", digitsOnly, i + 1, currentWindow));
                    }
                }

                //Password like
                foreach (Match m in PasswordLikeRx.Matches(line))
                    detections.Add(new Detection(filePath, "PasswordLike", m.Value, i + 1, currentWindow));
            }
            else
            {
                //non-sensitive window use default scanning
                foreach (Match m in EmailRx.Matches(line))
                    detections.Add(new Detection(filePath, "Email", m.Value, i + 1, currentWindow ?? "UNKNOWN"));

                //potential credit card but require Luhn 
                foreach (Match m in GenericCardRx.Matches(line))
                {
                    var digitsOnly = Regex.Replace(m.Value, @"[^\d]", "");
                    if (digitsOnly.Length >= 13 && digitsOnly.Length <= 19 && IsLuhnValid(digitsOnly))
                        detections.Add(new Detection(filePath, "CreditCard", digitsOnly, i + 1, currentWindow ?? "UNKNOWN"));
                }

                //SSN
                foreach (Match m in SsnRx.Matches(line))
                    detections.Add(new Detection(filePath, "SSN", m.Value, i + 1, currentWindow ?? "UNKNOWN"));
            }
        }

        return detections;
    }

    //Decides whether a window title is sensitive.
    static bool IsWindowSensitive(string title)
    {
        if (string.IsNullOrWhiteSpace(title)) return false;
        string low = title.ToLowerInvariant();

        foreach (var k in SensitiveWindowKeywords)
            if (low.Contains(k)) return true;

        foreach (var bank in BankNames)
            if (low.Contains(bank)) return true;

        //detect log in patterns
        if (low.Contains("log in") || low.Contains("login") || low.Contains("sign in") || low.Contains("signin"))
            return true;

        //titles that mention payment and potential credit card 
        if (low.Contains("checkout") || low.Contains("cart") || low.Contains("payment"))
            return true;

        return false;
    }

    //Luhn validation for credit cards
    static bool IsLuhnValid(string digits)
    {
        if (string.IsNullOrEmpty(digits) || digits.Any(c => !char.IsDigit(c))) return false;
        int sum = 0;
        bool alt = false;
        for (int i = digits.Length - 1; i >= 0; i--)
        {
            int d = digits[i] - '0';
            if (alt)
            {
                d *= 2;
                if (d > 9) d -= 9;
            }
            sum += d;
            alt = !alt;
        }
        return sum % 10 == 0;
    }

}