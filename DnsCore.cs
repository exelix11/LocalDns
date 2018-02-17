using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace LocalDns
{
    public class DnsCore
    {
        public bool FireEvents;
        public bool DenyNotInRules = false;
        public event ServerReadyHandler ServerReady;
        public event ConnectionRequestHandler ConnectionRequest;
        public event ResolvedIpHandler ResolvedIp;
        public event SocketExceptionHandler socketException;
        public delegate void ServerReadyHandler(Dictionary<string,string> e);
        public delegate void ConnectionRequestHandler(DnsConnectionRequestEventArgs e);
        public delegate void ResolvedIpHandler(DnsEventArgs e);
        public delegate void SocketExceptionHandler(SocketException ex);
        public Dictionary<string, DnsSettings> rules = new Dictionary<string, DnsSettings>();
        public IPAddress LocalHostIp = IPAddress.None; // NXDOMAIN

        Socket soc = null;
        EndPoint endpoint = null;

        public void RunDns()
        {
            setup();
            if (FireEvents && ServerReady != null) ServerReady(Helper.GetIPs());
            DnsMainLoop();
        }

        void setup()
        {
            soc = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            endpoint = new IPEndPoint(IPAddress.Any, 53);
            soc.ReceiveBufferSize = 1023;
            try
            {
                soc.Bind(endpoint);
            }
            catch (SocketException ex)
            {
                if (!FireEvents || socketException == null) throw (ex);
                else socketException(ex);
                return;
            }
        }

        void DnsMainLoop()
        {
            while (true)
            {
                byte[] data = new byte[1024];
                soc.ReceiveFrom(data, SocketFlags.None, ref endpoint);
                data = Helper.TrimArray(data);

                procRequest(data);                
            }
        }

        void procRequest(byte[] data)
        {
            string fullname = string.Join(".", GetName(data).ToArray());            
            if (FireEvents && ConnectionRequest != null)
            {
                DnsConnectionRequestEventArgs a = new DnsConnectionRequestEventArgs { Host = endpoint.ToString(), Url = fullname };
                ConnectionRequest(a);
            }

            string url = "";
            if (rules.ContainsKey(fullname))
            {
                if (rules[fullname].Mode == HandleMode.Allow) url = fullname;
                else if (rules[fullname].Mode == HandleMode.Redirect) url = rules[fullname].Address;
                else url = "NXDOMAIN";
            }
            else
            {
                if (!DenyNotInRules) url = fullname;
                else url = "NXDOMAIN";
            }

            IPAddress ip = LocalHostIp;
            if (url != "" && url != "NXDOMAIN")
            {
                try
                {
                    IPAddress address;
                    if (!IPAddress.TryParse(url, out address))
                    {
                        ip = Dns.GetHostEntry(url).AddressList[0];
                    }
                    else ip = address;
                }
                catch
                {
                    ip = IPAddress.None;
                }
            }

            byte[] res = MakeResponsePacket(data, ip);

            soc.SendTo(res, endpoint);

            if (FireEvents && ResolvedIp != null)
            {
                DnsEventArgs a = new DnsEventArgs() { Host = ip, Url = fullname };
                ResolvedIp(a);
            }
        }

        public List<string> GetName(byte[] Req)
        {
            List<string> addr = new List<string>();
            int type = (Req[2] >> 3) & 0xF;
            if (type == 0)
            {
                int lenght = Req[12];
                int i = 12;
                while (lenght > 0)
                {
                    byte[] tmp = new byte[i + lenght];
                    Buffer.BlockCopy(Req, i + 1, tmp, 0, lenght);
                    string partialaddr = Helper.TrimString(tmp);
                    if (partialaddr != null) addr.Add(partialaddr);
                    i += (lenght + 1);
                    lenght = Req[i];
                }
            }
            return addr;
        }
        
        public byte[] MakeResponsePacket(byte[] Req, IPAddress Ip)
        {
            List<byte> ans = new List<byte>();
            //http://www.ccs.neu.edu/home/amislove/teaching/cs4700/fall09/handouts/project1-primer.pdf
            //Header
            ans.AddRange(new byte[] { Req[0], Req[1] });//ID
            if (Ip == IPAddress.None)
                ans.AddRange(new byte[] { 0x81, 0x83 });
            else
                ans.AddRange(new byte[] { 0x81, 0x80 }); //OPCODE & RCODE etc...
            ans.AddRange(new byte[] { Req[4], Req[5] });//QDCount
            ans.AddRange(new byte[] { Req[4], Req[5] });//ANCount
            ans.AddRange(new byte[4]);//NSCount & ARCount

            for (int i = 12; i < Req.Length; i++) ans.Add(Req[i]);
            ans.AddRange(new byte[] { 0xC0, 0xC });

            if (Ip.AddressFamily == AddressFamily.InterNetworkV6)
                ans.AddRange(new byte[] { 0, 0x1c, 0, 1, 0, 0, 0, 0x14, 0, 0x10  }); //20 seconds, 0x10 is ipv6 length
            else
                ans.AddRange(new byte[] { 0, 1, 0, 1, 0, 0, 0, 0x14, 0, 4 }); 
            ans.AddRange(Ip.GetAddressBytes());

            return ans.ToArray();
        }
    }

    public struct DnsSettings
    {
        public string Address; //For redirect to
        public HandleMode Mode;
    }

    public struct DnsEventArgs
    {
        public IPAddress Host;
        public string Url;
    }

    public struct DnsConnectionRequestEventArgs
    {
        public string Host;
        public string Url;
    }

    public enum HandleMode
    {
        Deny,
        Allow,
        Redirect
    }

    public static class Helper
    {
        public static Dictionary<string, string> GetIPs()
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

        public static byte[] TrimArray(byte[] arr)
        {
            int i = arr.Length - 1;
            while (arr[i] == 0) i--;
            byte[] data = new byte[i + 1];
            Array.Copy(arr, data, i + 1);
            return data;
        }

        public static string TrimString(byte[] str)
        {
            int i = str.Length - 1;
            while (str[i] == 0)
            {
                Array.Resize(ref str, i);
                i -= 1;
            }
            string res = Encoding.ASCII.GetString(str);
            //if (res.ToLower() == "www") return null; Some sites do not work without www
           /* else*/ return res;
        }
    }
}
