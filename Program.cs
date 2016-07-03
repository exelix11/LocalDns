using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.VisualBasic;
using System.Collections;
using System.Data;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Net.NetworkInformation;

namespace LocalDns
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Title = "LocalDns";
            Console.WriteLine("LocalDns By Exelix11");
            if (args.Length > 2) PrintHelp();
            else if (args.Length == 0)
            {
                if (File.Exists("List.txt")) RunDns(File.ReadAllLines("List.txt"), "127.0.0.1");
                else PrintHelp();
            }
            else
            {
                RunDns(File.ReadAllLines(args[0]), args.Length == 1 ? "127.0.0.1" : args[1]);
            }
        }

        static void PrintHelp()
        {
            Console.WriteLine("_____________________________________________");
            Console.WriteLine("Usage:");
            Console.WriteLine("LocalDns.exe [blacklist as txt] [ip]");
            Console.WriteLine("Redirects every address in the list to 127.0.0.1 or the ip you set, the list must contain one address per line without 'www', List.txt is loaded by default");
            Console.WriteLine("Addresses not in the list will be resolved with your pc's dns");
            Console.ReadKey();
        }

        static void RunDns(string[] BlockList, string localhost)
        {
            Console.WriteLine("Starting DNS... (Press CTRL + C to close)");
            Console.Title = "LocalDns, press CTRL + C to exit";
            Console.WriteLine("_____________________________________________");
            Socket s = new Socket(SocketType.Dgram, ProtocolType.Udp);
            EndPoint e = new IPEndPoint(IPAddress.Any, 53);
            s.ReceiveBufferSize = 1023;
            s.Bind(e);
            Dictionary<string, string> IPs = GetIPs();
            switch (IPs.Keys.Count)
            {
                case 0:
                    Console.WriteLine("Socket ready");
                    Console.WriteLine("WARNING: no local ip address found");
                    break;
                case 1:
                    Console.WriteLine("Socket ready, running on " + IPs.Keys.ToArray()[0]);
                    break;
                default:
                    Console.WriteLine("Socket ready, running on: (an ip for every network interface)");
                    foreach (string k in IPs.Keys.ToArray()) Console.WriteLine(k + " on " + IPs[k]);
                    break;
            }
            Console.WriteLine("_____________________________________________");
            while (true)
            {
                byte[] data = new byte[1024];
                s.ReceiveFrom(data, SocketFlags.None, ref e);
                Console.WriteLine("Got request from: " + e.ToString());
                int i = s.ReceiveBufferSize;
                while (data[i] == 0)
                {
                    Array.Resize(ref data, i);
                    i -= 1;
                }
                DnsAnswer server = new DnsAnswer(data);
                string fullname = string.Join(".", server.addr);
                byte[] res;
                if (BlockList.Contains(fullname.ToLower())) res = server.GetResponse(localhost, "");
                else res = server.GetResponse(localhost, fullname);
                Console.WriteLine("Resolved: " + fullname + " to: " + server.IpRes);
                s.SendTo(res, e);
            }
        }

        static Dictionary<string,string> GetIPs()
        {
            Dictionary<string, string> addresses = new Dictionary<string, string>();
            NetworkInterface[] allInterfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface n in allInterfaces)
            {
                if (n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 || n.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
                {
                    foreach (UnicastIPAddressInformation ip in n.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            addresses.Add(ip.Address.ToString(), n.Name);
                        }
                    }
                }
            }
            return addresses;
        }
    }

    class DnsAnswer
    {
        public List<string> addr = new List<string>();
        public string IpRes = "";
        byte[] Req;

        public DnsAnswer(byte[] Request)
        {
            Req = Request;
            int type = (Req[2] >> 3) & 0xF;
            if (type == 0)
            {
                int lenght = Req[12];
                int i = 12;
                while (lenght > 0)
                {
                    byte[] tmp = new byte[i + lenght];
                    Buffer.BlockCopy(Req, i + 1, tmp, 0, lenght);
                    string partialaddr = GetStringTrim(tmp);
                    if (partialaddr != null) addr.Add(partialaddr);
                    i += (lenght + 1);
                    lenght = Req[i];
                }
            }
        }

        string GetStringTrim(byte[] str)
        {
            int i = str.Length - 1;
            while (str[i] == 0)
            {
                Array.Resize(ref str, i);
                i -= 1;
            }
            string res = Encoding.ASCII.GetString(str);
            if (res.ToLower() == "www") return null;
            else return res;
        }

        public byte[] GetResponse(string ip, string redirect)
        {
            List<byte> ans = new List<byte>();
            //http://www.ccs.neu.edu/home/amislove/teaching/cs4700/fall09/handouts/project1-primer.pdf
            //Header
            ans.AddRange(new byte[] { Req[0], Req[1] });//ID
            ans.AddRange(new byte[] { 0x81, 0x80 }); //OPCODE & RCODE etc...
            ans.AddRange(new byte[] { Req[4], Req[5] });//QDCount
            ans.AddRange(new byte[] { Req[4], Req[5] });//ANCount
            ans.AddRange(new byte[4]);//NSCount & ARCount

            for (int i = 12; i < Req.Length; i++) ans.Add(Req[i]);
            ans.AddRange(new byte[] { 0xC0, 0xC });
            ans.AddRange(new byte[] { 0, 1, 0, 1, 0, 0, 0, 0x3c, 0, 4 }); //60 seconds
            if (redirect != "")
                try { ans.AddRange(ParseIp(Dns.GetHostEntry(redirect).AddressList[0].ToString())); }
                catch { ans.AddRange(ParseIp(ip)); }
            else ans.AddRange(ParseIp(ip));

            return ans.ToArray();
        }

        byte[] ParseIp(string ip)
        {
            byte[] ip4 = new byte[4];
            string[] ipstring = ip.Split('.');
            ip4[0] = Byte.Parse(ipstring[0]);
            ip4[1] = Byte.Parse(ipstring[1]);
            ip4[2] = Byte.Parse(ipstring[2]);
            ip4[3] = Byte.Parse(ipstring[3]);
            IpRes = ip;
            return ip4;
        }
    }
}
