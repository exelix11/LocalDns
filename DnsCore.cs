using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

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
        public delegate void ConnectionRequestHandler(DnsEventArgs e);
        public delegate void ResolvedIpHandler(DnsEventArgs e);
        public delegate void SocketExceptionHandler(SocketException ex);
        public Dictionary<string, DnsSettings> rules = new Dictionary<string, DnsSettings>();
        public string LocalHostIp = "NXDOMAIN";

        public void RunDns()
        {
            run();
        }

        Task run()
        {
            Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            EndPoint e = new IPEndPoint(IPAddress.Any, 53);
            s.ReceiveBufferSize = 1023;
            try
            {
                s.Bind(e);
            }
            catch (SocketException ex)
            {
                if (!FireEvents || socketException == null) throw (ex);
                else socketException(ex);
                return null;
            }
            if (FireEvents && ServerReady != null) ServerReady(Helper.GetIPs());
            while (true)
            {
                byte[] tdata = new byte[1024];
                s.ReceiveFrom(tdata, SocketFlags.None, ref e);
                int i = tdata.Length - 1;
                while (tdata[i] == 0) i--;
                byte[] data = new byte[i + 1];
                Array.Copy(tdata, data, i + 1);
                string fullname = string.Join(".", GetName(data).ToArray());
                byte[] res;
                if (FireEvents && ConnectionRequest != null)
                {
                    DnsEventArgs a;
                    a.Host = e.ToString();
                    a.Url = fullname;
                    ConnectionRequest(a);
                }
                string url = "";
                Debug.WriteLine(rules.ContainsKey(fullname));
                if (rules.ContainsKey(fullname))
                {
                    if (rules[fullname].Mode == HandleMode.Allow) url = fullname;
                    else if (rules[fullname].Mode == HandleMode.Redirect) url = rules[fullname].Address;
                }
                else
                {
                    if (!DenyNotInRules) url = fullname;
                }
                string ip = LocalHostIp;
                if (url != "" && url!="NXDOMAIN")
                {
                    try
                    {
                        IPAddress a;
                        if (!IPAddress.TryParse(url, out a))
                        {
                            var t = Dns.GetHostEntry(url).AddressList;
                            Debug.WriteLine(t.Length);
                            ip = t[0].ToString();
                        }
                        else ip = url;
                    }
                    catch 
                    {
                        ip = "NXDOMAIN";
                    }
                }
                res = MakeResponsePacket(data, ip);
                if (FireEvents && ResolvedIp != null)
                {
                    DnsEventArgs a;
                    a.Host = ip;
                    a.Url = fullname;
                    ResolvedIp(a);
                }
                s.SendTo(res, e);
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

        public byte[] MakeResponsePacket(byte[] Req, string Ip)
        {
            List<byte> ans = new List<byte>();
            //http://www.ccs.neu.edu/home/amislove/teaching/cs4700/fall09/handouts/project1-primer.pdf
            //Header
            ans.AddRange(new byte[] { Req[0], Req[1] });//ID
            if (Ip == "NXDOMAIN")
                ans.AddRange(new byte[] { 0x81, 0x83 });
            else
                ans.AddRange(new byte[] { 0x81, 0x80 }); //OPCODE & RCODE etc...
            ans.AddRange(new byte[] { Req[4], Req[5] });//QDCount
            ans.AddRange(new byte[] { Req[4], Req[5] });//ANCount
            ans.AddRange(new byte[4]);//NSCount & ARCount

            for (int i = 12; i < Req.Length; i++) ans.Add(Req[i]);
            ans.AddRange(new byte[] { 0xC0, 0xC });
            ans.AddRange(new byte[] { 0, 1, 0, 1, 0, 0, 0, 0x14, 0, 4 }); //20 seconds
            ans.AddRange(Helper.ParseIp(Ip));

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

       public static byte[] ParseIp(string ip)
        {
            if (ip == "NXDOMAIN") return new byte[4];
            byte[] ip4 = new byte[4];
            string[] ipstring = ip.Split('.');
            ip4[0] = Byte.Parse(ipstring[0]);
            ip4[1] = Byte.Parse(ipstring[1]);
            ip4[2] = Byte.Parse(ipstring[2]);
            ip4[3] = Byte.Parse(ipstring[3]);
            return ip4;
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
