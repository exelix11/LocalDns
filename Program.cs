using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LocalDns
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Title = "LocalDns";
            Console.WriteLine("LocalDns By Exelix11");
            if (args.Length > 3) { PrintHelp(); return; }
            Dictionary<string, DnsSettings> rules = null;
            DnsCore Dns = new LocalDns.DnsCore();
            if (args.Length == 0)
            {
                if (File.Exists("Rules.txt"))
                {
                    rules = ParseRules("Rules.txt");
                }
                else { PrintHelp(); return; }
            }
            else
            {
                if (File.Exists(args[0]))
                {
                    rules = ParseRules(args[0]);
                }
                else { Console.WriteLine(args[0] + "not found !"); PrintHelp(); return; }
                if (args.Length > 1)
                {
                    Dns.DenyNotInRules = Convert.ToBoolean(args[1]);
                }
                if (args.Length == 3) Dns.LocalHostIp = args[2].Trim();
            }
            if (rules != null) Dns.rules = rules;
            Dns.FireEvents = true;
            Dns.ResolvedIp += ResolvedIp;
            Dns.ConnectionRequest += ConnectionRequest;
            Dns.ServerReady += ServerReady;
            Dns.RunDns();
        }

        private static void ServerReady(Dictionary<string, string> e)
        {
            Console.WriteLine("Starting DNS... (Press CTRL + C to close)");
            Console.Title = "LocalDns, press CTRL + C to exit";
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

        static Dictionary<string, DnsSettings> ParseRules(string Filename)
        {
            Dictionary<string, DnsSettings> res = new Dictionary<string, DnsSettings>();
            string[] rules = File.ReadAllLines(Filename);
            foreach (string s in rules)
            {
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
                res.Add(split[0].Trim(), dns);
                res.Add("www." + split[0].Trim(), dns);
            }
            Console.WriteLine(res.Count.ToString() + " rules loaded");
            if (System.Diagnostics.Debugger.IsAttached)
            {
                List<string[]> ToPad = new List<string[]>();
                foreach (string s in res.Keys.ToArray()) ToPad.Add( new string[] { s, res[s].Mode.ToString(), res[s].Address == null ? "" : res[s].Address });
                Console.WriteLine(ConsoleUtility.PadElementsInLines(ToPad, 5));
            }
            return res;
        }

        static void PrintHelp()
        {
            Console.WriteLine("_____________________________________________");
            Console.WriteLine("Usage:");
            Console.WriteLine("LocalDns.exe [rules, default is : Rules.txt] [BlockNotInList: True|False, default is: false] [Localhost, default is NXDOMAIN]");
            Console.WriteLine("The rules file must be a txt, each line must contain a rule in this format:\r\n"+
                "*url*,*action: Deny|Allow|Redirect*,[Optional RedirectUrl]\r\n"+
                "   Examples:\r\n"+
                "   Example.com,Deny\r\n" +
                "   This will redirect every Examples.com query to the Localhost address\r\n" +
                "   Example.com,Redirect,Examples2.com\r\n" +
                "   This will redirect Example.com to Examples2.com\r\n"+
                "   Example.com,Allow\r\n"+
                "   This will resolve Example.com to the real address, use this with BlockNotInList set to true, so every other site will be redirected to LocalHost");
            Console.WriteLine("BlockNotInList: If set to true will redirect to Localhost urls not in the rules file, else will return the real address");
            Console.WriteLine("Localhost: the ip to redirect every blocked url (like 127.0.0.1),if set to NXDOMAIN the domain not found error will be sent instead of an ip");
            Console.ReadKey();
        }

        private static void ResolvedIp(DnsEventArgs e)
        {
            Console.WriteLine("Resolved: " + e.Url + " to: " + e.Host);
        }

        private static void ConnectionRequest(DnsEventArgs e)
        {
            Console.WriteLine("Got request from: " + e.Host);
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
