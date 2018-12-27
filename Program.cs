using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace LocalDns
{
    class Program
    {
        const uint ENABLE_QUICK_EDIT = 0x0040;
        const int STD_INPUT_HANDLE = -10;
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetStdHandle(int nStdHandle);

        [DllImport("kernel32.dll")]
        static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

        [DllImport("kernel32.dll")]
        static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

        static bool MONO = false;
        static string RulesUrl = @"https://raw.githubusercontent.com/exelix11/LocalDns/master/Rules.txt";
        static void Main(string[] args)
        {
            MONO = Type.GetType("Mono.Runtime") != null;
            if (!MONO) //Is running on windows ?
            {
                //this disables select in the cmd window
                IntPtr consoleHandle = GetStdHandle(STD_INPUT_HANDLE);
                uint consoleMode;
                GetConsoleMode(consoleHandle, out consoleMode);
                consoleMode &= ~ENABLE_QUICK_EDIT;
                SetConsoleMode(consoleHandle, consoleMode);
            }            
            Console.Title = "LocalDNS";
            Console.WriteLine("LocalDNS 1.2 By Exelix11");
            Console.WriteLine("https://github.com/exelix11/LocalDns");
            Console.WriteLine("");

            Dictionary<string, DnsSettings> dicRules = null;
            List<KeyValuePair<string, DnsSettings>> regRules = null;
            DnsCore Dns = new LocalDns.DnsCore();

            #region parseArgs
            bool DownloadRules = false; //Uhhh bad code :(
            if (args.Length != 0)
            {
                try
                {
                    for (int i = 0; i < args.Length; i++)
                    {
                        if ((args[i].StartsWith("-") || args[i].StartsWith(@"\") || args[i].StartsWith("/")) && args[i].Length > 1) args[i] = args[i].Remove(0, 1);
                        switch (args[i].ToLower())
                        {
                            case "?":
                            case "h":
                            case "help":
                                PrintHelp();
                                return;
                            case "downloadrules":
                                DownloadRules = true;
                                break;
                            case "rules":
                                if (DownloadRules) break;
                                if (File.Exists(args[i + 1]))
                                {
                                    ParseRules(args[i + 1], out dicRules, out regRules);
                                }
                                else
                                {
                                    Console.WriteLine("_____________________________________________\r\n" + args[i + 1] + " not found !");
                                    PrintHelp();
                                    return;
                                }
                                break;
                            case "blocknotinrules":
                                Dns.DenyNotInRules = args[i + 1].ToLower() == "true";
                                break;
                            case "localhost":
                                {
                                    string ipStr = args[i + 1].Trim();
                                    IPAddress ipAddr;
                                    if (IPAddress.TryParse(ipStr, out ipAddr))
                                    {
                                        Dns.LocalHostIp = ipAddr;
                                    }
                                    else Console.WriteLine("Warning: Couldn't parse '{ipStr}' as an IP address");
                                }
                                break;
                        }
                    }
                }
                catch
                {
                    Console.WriteLine("Can't parse args !");
                    PrintHelp();
                    return;
                }
            }
            #endregion
            if (DownloadRules)
            {
                Console.WriteLine("Downloading rules.....");
                if (MONO) ServicePointManager.ServerCertificateValidationCallback = MyRemoteCertificateValidationCallback;
                Dns.DenyNotInRules = false;
                HttpWebRequest http = (HttpWebRequest)WebRequest.Create(RulesUrl);
                WebResponse response = http.GetResponse();
                StreamReader sr = new StreamReader(response.GetResponseStream());
                string content = sr.ReadToEnd();
                ParseRules(content, out dicRules, out regRules, false);
            }
            else if (dicRules == null)
            {
                if (File.Exists("Rules.txt"))
                {
                    ParseRules("Rules.txt", out dicRules, out regRules);
                }
                else
                {
                    Console.WriteLine("_____________________________________________\r\nRules.txt not found !");
                    PrintHelp();
                    return;
                }
            }
            if (System.Diagnostics.Debugger.IsAttached)
            {
                Console.WriteLine("BlockNotInRules: " + Dns.DenyNotInRules.ToString());
                Console.WriteLine("localhost: " + Dns.LocalHostIp.ToString());
            }

            Dns.dicRules = dicRules;
            Dns.regRules = regRules;
            Dns.FireEvents = true;
            Dns.ResolvedIp += ResolvedIp;
            Dns.ConnectionRequest += ConnectionRequest;
            Dns.ServerReady += ServerReady;
            Dns.socketException += BindError;
            Dns.RunDns();
        }

        private static void BindError(SocketException ex)
        {
            Console.WriteLine("_____________________________________________");
            Console.WriteLine("Couldn't bind to port 53.");
            Console.WriteLine("It may be already in use, on windows check with \"netstat -ano\"\r\nIf you're on linux make sure to run with sudo");
            Console.WriteLine("Error message: " + ex.Message);
            Console.ReadLine();
        }

        private static void ServerReady(Dictionary<string, string> e)
        {
            Console.WriteLine("Starting DNS... (Press CTRL + C to close)");
            Console.Title = "LocalDNS, press CTRL + C to exit";
            Console.WriteLine("_____________________________________________");
            switch (e.Keys.Count)
            {
                case 0:
                    Console.WriteLine("Socket ready");
                    Console.WriteLine("WARNING: no local ip address found");
                    break;
                case 1:
                    Console.WriteLine("Socket ready, running on " + e.Keys.ToArray()[0]);
                    break;
                default:
                    Console.WriteLine("Socket ready, running on: (an ip for every network interface)");
                    foreach (string k in e.Keys.ToArray()) Console.WriteLine(k + " on " + e[k]);
                    break;
            }
            Console.WriteLine("_____________________________________________");
        }

        static void ParseRules(string Filename, out Dictionary<string, DnsSettings> DicRules, out List<KeyValuePair<string, DnsSettings>> StarRules, bool IsFilename = true)
        {
            DicRules = new Dictionary<string,DnsSettings>();
            StarRules = new List<KeyValuePair<string, DnsSettings>>();

            string[] rules = IsFilename ? File.ReadAllLines(Filename) : Filename.Split(new string[] { "\r\n", "\n" }, StringSplitOptions.None);
            foreach (string s in rules)
            {
                if (s.StartsWith(";") || s.Trim() == "") continue;
                string[] split = s.Split(',');
                DnsSettings dns = new DnsSettings();
                switch (split[1].Trim().ToLower())
                {
                    case "deny":
                        dns.Mode = HandleMode.Deny;
                        break;
                    case "allow":
                        dns.Mode = HandleMode.Allow;
                        break;
                    case "redirect":
                        dns.Mode = HandleMode.Redirect;
                        dns.Address = split[2].Trim();
                        break;
                    default:
                        throw new Exception("Can't parse rules !");
                }

                string domain = split[0].Trim();
                if (domain.Contains("*"))
                {
                    domain = domain.Replace(".", "\\.");
                    domain = domain.Replace("*", ".*");
                    StarRules.Add(new KeyValuePair<string, DnsSettings>(domain, dns));
                }
                else
                {
                    DicRules.Add(domain, dns);
                    DicRules.Add("www." + domain, dns);
                }
            }

            Console.WriteLine(DicRules.Count.ToString() + " dictionary rules and " + StarRules.Count.ToString() + " star rules loaded");
            if (System.Diagnostics.Debugger.IsAttached)
            {
                List<string[]> ToPad = new List<string[]>();
                foreach (string s in DicRules.Keys.ToArray()) ToPad.Add(new string[] { s, DicRules[s].Mode.ToString(), DicRules[s].Address == null ? "" : DicRules[s].Address });
                foreach (KeyValuePair<string, DnsSettings> rule in StarRules) ToPad.Add(new string[] { rule.Key, rule.Value.Mode.ToString(), rule.Value.Address == null ? "" : rule.Value.Address });
                Console.WriteLine(ConsoleUtility.PadElementsInLines(ToPad, 5));
            }
        }

        static void PrintHelp()
        {
            Console.WriteLine("_____________________________________________");
            Console.WriteLine("Usage:");
            Console.WriteLine("LocalDns.exe [-Rules Rules.txt] [-BlockNotInRules false] [-LocalHost NXDOMAIN]");
            Console.WriteLine("-Localhost:  the ip to redirect every blocked url (like 127.0.0.1),by default is set to NXDOMAIN, by doing so the domain not found error will be sent instead of an ip");
            Console.WriteLine("-DownloadRules: Uses the latest rules file from the github repo, doesn't overwrite Rules.txt, if set, -Rules and -BlockNotInRule will be ignored");
            Console.WriteLine("-Rules : Specifies a rules file, if not set Rules.txt is loaded by default. Don't use spaces in the path !");
            Console.WriteLine("-BlockNotInRules: only true or false, if set to true will redirect to Localhost urls not in the rules file, else will return the real address, by default is set to false");
            Console.ReadKey();
        }

        private static void ResolvedIp(DnsEventArgs e)
        {
            Console.WriteLine("Resolved: " + e.Url + " to: " + ((e.Host == IPAddress.None) ? "NXDOMAIN" : e.Host.ToString()));
        }

        private static void ConnectionRequest(DnsConnectionRequestEventArgs e)
        {
            Console.WriteLine("Got request from: " + e.Host);
        }

        static public bool MyRemoteCertificateValidationCallback(System.Object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true; //This isn't a good thing to do, but to keep the code simple i prefer doing this, it will be used only on mono
        }
    }
}

// Source: http://dev.flauschig.ch/wordpress/?p=387
public static class ConsoleUtility
{
    /// <summary>
    /// Converts a List of string arrays to a string where each element in each line is correctly padded.
    /// Make sure that each array contains the same amount of elements!
    /// - Example without:
    /// Title Name Street
    /// Mr. Roman Sesamstreet
    /// Mrs. Claudia Abbey Road
    /// - Example with:
    /// Title   Name      Street
    /// Mr.     Roman     Sesamstreet
    /// Mrs.    Claudia   Abbey Road
    /// <param name="lines">List lines, where each line is an array of elements for that line.</param>
    /// <param name="padding">Additional padding between each element (default = 1)</param>
    /// </summary>
    public static string PadElementsInLines(List<string[]> lines, int padding = 1)
    {
        // Calculate maximum numbers for each element accross all lines
        var numElements = lines[0].Length;
        var maxValues = new int[numElements];
        for (int i = 0; i < numElements; i++)
        {
            maxValues[i] = lines.Max(x => x[i].Length) + padding;
        }

        var sb = new StringBuilder();
        // Build the output
        bool isFirst = true;
        foreach (var line in lines)
        {
            if (!isFirst)
            {
                sb.AppendLine();
            }
            isFirst = false;

            for (int i = 0; i < line.Length; i++)
            {
                var value = line[i];
                // Append the value with padding of the maximum length of any value for this element
                sb.Append(value.PadRight(maxValues[i]));
            }
        }
        return sb.ToString();
    }
}
