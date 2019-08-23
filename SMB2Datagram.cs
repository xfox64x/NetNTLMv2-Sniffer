using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PcapDotNet.Packets;

namespace NetNTLMSniff
{
    class SMB2Datagram
    {

        public enum SMB2CommandNames { NEGOTIATE, SESSION_SETUP, LOGOFF, TREE_CONNECT, TREE_DISCONNECT, CREATE, CLOSE, FLUSH, READ, WRITE, LOCK, IOCTL, CANCEL, ECHO, QUERY_DIRECTORY, CHANGE_NOTIFY, QUERY_INFO, SET_INFO, OPLOCK_BREAK, UNSET };
        public enum SESSION_SETUP_Response_Flag_Names { SMB2_SESSION_FLAG_IS_GUEST, SMB2_SESSION_FLAG_IS_NULL, SMB2_SESSION_UNKNOWN, SMB2_SESSION_FLAG_ENCRYPT_DATA };
        public enum NTLMMessageType { Unknown, NtLmNegotiate, NtLmChallenge, NtLmAuthenticate }
        public static byte[] NTLMSSPstring = new byte[] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00 };
        
        public class NTLMSSP_MESSAGE
        {

            public ulong Signature = 0;
            public NTLMMessageType MessageType = NTLMMessageType.Unknown;
            public enum AvIds { MsvAvEOL, MsvAvNbComputerName, MsvAvNbDomainName, MsvAvDnsComputerName, MsvAvDnsDomainName, MsvAvDnsTreeName, MsvAvFlags, MsvAvTimestamp, MsvAvSingleHost, MsvAvTargetName, MsvChannelBindings };
            public Hashtable AttributeValuePairs = new Hashtable();

            public NTLMSSP_MESSAGE(DataSegment commandDataArg)
            {
                var packetDataArray = commandDataArg.ToArray();
                Signature = packetDataArray.ReadULong(0, Endianity.Big);
                try
                {
                    MessageType = (NTLMMessageType)packetDataArray.ReadUInt(8, Endianity.Small);
                }
                catch
                {
                    MessageType = NTLMMessageType.Unknown;
                }
                
            }

            public void ParseAttributeValuePairs(DataSegment attributeValueData)
            {
                var attributeValueArray = attributeValueData.ToArray();

                int offset = 0;
                bool shouldBreak = false;
                while (offset < (attributeValueArray.Length - 4) && !shouldBreak)
                {
                    try
                    {
                        AvIds AvId = (AvIds)attributeValueArray.ReadUShort((0 + offset), Endianity.Small);
                        ushort AvLen = attributeValueArray.ReadUShort((2 + offset), Endianity.Small);
                        if ((AvLen + offset + 4) < attributeValueArray.Length)
                        {
                            byte[] RawValue = attributeValueData.Subsegment((offset + 4), AvLen).ToArray();

                            switch (AvId)
                            {
                                // Indicates that this is the last AV_PAIR in the list.
                                case AvIds.MsvAvEOL:
                                    shouldBreak = true;
                                    break;

                                case AvIds.MsvAvNbComputerName:
                                case AvIds.MsvAvNbDomainName:
                                case AvIds.MsvAvDnsComputerName:
                                case AvIds.MsvAvDnsDomainName:
                                case AvIds.MsvAvDnsTreeName:
                                case AvIds.MsvAvTargetName:
                                    try
                                    {
                                        AttributeValuePairs.Add(AvId.ToString(), Encoding.Unicode.GetString(RawValue, 0, RawValue.Length));
                                    }
                                    catch
                                    {
                                        AttributeValuePairs.Add(AvId.ToString(), "Issue parsing attribute.");
                                    };
                                    break;

                                case AvIds.MsvAvFlags:
                                case AvIds.MsvAvTimestamp:
                                case AvIds.MsvAvSingleHost:
                                case AvIds.MsvChannelBindings:
                                    break;

                                default:
                                    break;
                            }
                            
                            offset = (AvLen + offset + 4);
                        }
                        else
                        {
                            break;
                        }
                    }
                    catch
                    {
                        break;
                    }
                }
            }
        }

        public class NTLMSSP_CHALLENGE_MESSAGE : NTLMSSP_MESSAGE
        {
            public ushort TargetNameLen = 0;
            public ushort TargetNameMaxLen = 0;
            public uint TargetNameBufferOffset = 0;
            public uint NegotiateFlags = 0;
            public DataSegment ServerChallenge = null;
            public ulong ReservedField1 = 0;
            public ushort TargetInfoLen = 0;
            public ushort TargetInfoMaxLen = 0;
            public uint TargetInfoBufferOffset = 0;
            public ulong Version = 0;
            public DataSegment Payload = null;
            public string TargetName = null;
            
            public NTLMSSP_CHALLENGE_MESSAGE(DataSegment commandDataArg) : base(commandDataArg)
            {
                var packetDataArray = commandDataArg.ToArray();
                
                TargetNameLen = packetDataArray.ReadUShort(12, Endianity.Small);
                TargetNameMaxLen = packetDataArray.ReadUShort(14, Endianity.Small);
                TargetNameBufferOffset = packetDataArray.ReadUInt(16, Endianity.Small);
                NegotiateFlags = packetDataArray.ReadUInt(20, Endianity.Small);
                ServerChallenge = commandDataArg.Subsegment(24, 8);//  packetDataArray.ReadULong(24, Endianity.Big);
                ReservedField1 = packetDataArray.ReadULong(32, Endianity.Small);
                TargetInfoLen = packetDataArray.ReadUShort(40, Endianity.Small);
                TargetInfoMaxLen = packetDataArray.ReadUShort(42, Endianity.Small);
                TargetInfoBufferOffset = packetDataArray.ReadUInt(44, Endianity.Small);
                Version = packetDataArray.ReadULong(48, Endianity.Big);
                Payload = commandDataArg.Subsegment(56, (commandDataArg.Length - 56));
                
                var payloadDataArray = Payload.ToArray();
                
                if (TargetNameLen > 0 && (TargetNameBufferOffset + TargetNameLen) < packetDataArray.Length)
                {
                    var TargetNameByteArray = packetDataArray.Subsegment(Convert.ToInt32(TargetNameBufferOffset), TargetNameLen).ToArray();
                    TargetName = Encoding.Unicode.GetString(TargetNameByteArray, 0, TargetNameByteArray.Length);
                }

                if(TargetInfoLen > 0 && (TargetInfoBufferOffset + TargetInfoLen) < packetDataArray.Length)
                {
                    ParseAttributeValuePairs(packetDataArray.Subsegment(Convert.ToInt32(TargetInfoBufferOffset), TargetInfoLen));
                }   
            }
        }

        public class NTLMSSP_AUTHENTICATE_MESSAGE : NTLMSSP_MESSAGE
        {
            public ushort LmChallengeResponseLen = 0;
            public ushort LmChallengeResponseMaxLen = 0;
            public uint LmChallengeResponseBufferOffset = 0;
            public ushort NtChallengeResponseLen = 0;
            public ushort NtChallengeResponseMaxLen = 0;
            public uint NtChallengeResponseBufferOffset = 0;
            public ushort DomainNameLen = 0;
            public ushort DomainNameMaxLen = 0;
            public uint DomainNameBufferOffset = 0;
            public ushort UserNameLen = 0;
            public ushort UserNameMaxLen = 0;
            public uint UserNameBufferOffset = 0;
            public ushort WorkstationLen = 0;
            public ushort WorkstationMaxLen = 0;
            public uint WorkstationBufferOffset = 0;
            public ushort EncryptedRandomSessionKeyLen = 0;
            public ushort EncryptedRandomSessionKeyMaxLen = 0;
            public uint EncryptedRandomSessionKeyBufferOffset = 0;
            public uint NegotiateFlags = 0;
            public ulong Version = 0;
            public DataSegment MIC;
            public DataSegment Payload = null;
            public DataSegment LmChallengeResponse;
            public DataSegment NtChallengeResponse;
            public string DomainName;
            public string UserName;
            public string Workstation;
            public DataSegment EncryptedRandomSessionKey;
            public bool Is_NTLMv2_Response = true;
            public byte RespType;
            public byte HiRespType;
            public ushort Reserved1;
            public uint Reserved2;
            public uint Reserved3;
            public ulong TimeStamp;
            public ulong ChallengeFromClient;

            public NTLMSSP_AUTHENTICATE_MESSAGE(DataSegment commandDataArg) : base(commandDataArg)
            {
                var packetDataArray = commandDataArg.ToArray();

                LmChallengeResponseLen = packetDataArray.ReadUShort(12, Endianity.Small);
                LmChallengeResponseMaxLen = packetDataArray.ReadUShort(14, Endianity.Small);
                LmChallengeResponseBufferOffset = packetDataArray.ReadUInt(16, Endianity.Small);

                NtChallengeResponseLen = packetDataArray.ReadUShort(20, Endianity.Small);
                NtChallengeResponseMaxLen = packetDataArray.ReadUShort(22, Endianity.Small);
                NtChallengeResponseBufferOffset = packetDataArray.ReadUInt(24, Endianity.Small);

                DomainNameLen = packetDataArray.ReadUShort(28, Endianity.Small);
                DomainNameMaxLen = packetDataArray.ReadUShort(30, Endianity.Small);
                DomainNameBufferOffset = packetDataArray.ReadUInt(32, Endianity.Small);

                UserNameLen = packetDataArray.ReadUShort(36, Endianity.Small);
                UserNameMaxLen = packetDataArray.ReadUShort(38, Endianity.Small);
                UserNameBufferOffset = packetDataArray.ReadUInt(40, Endianity.Small);

                WorkstationLen = packetDataArray.ReadUShort(44, Endianity.Small);
                WorkstationMaxLen = packetDataArray.ReadUShort(46, Endianity.Small);
                WorkstationBufferOffset = packetDataArray.ReadUInt(48, Endianity.Small);

                EncryptedRandomSessionKeyLen = packetDataArray.ReadUShort(52, Endianity.Small);
                EncryptedRandomSessionKeyMaxLen = packetDataArray.ReadUShort(54, Endianity.Small);
                EncryptedRandomSessionKeyBufferOffset = packetDataArray.ReadUInt(56, Endianity.Small);

                NegotiateFlags = packetDataArray.ReadUInt(60, Endianity.Small);
                Version = packetDataArray.ReadULong(64, Endianity.Big);
                MIC = commandDataArg.Subsegment(72, 16);
                Payload = commandDataArg.Subsegment(88, (commandDataArg.Length - 88));

                var payloadDataArray = Payload.ToArray();

                if (LmChallengeResponseLen > 0 && (LmChallengeResponseBufferOffset + LmChallengeResponseLen) < packetDataArray.Length)
                {
                    LmChallengeResponse = packetDataArray.Subsegment(Convert.ToInt32(LmChallengeResponseBufferOffset), LmChallengeResponseLen);
                }

                if (NtChallengeResponseLen > 0 && (NtChallengeResponseBufferOffset + NtChallengeResponseLen) < packetDataArray.Length)
                {
                    NtChallengeResponse = packetDataArray.Subsegment(Convert.ToInt32(NtChallengeResponseBufferOffset), NtChallengeResponseLen);
                }

                if (DomainNameLen > 0 && (DomainNameBufferOffset + DomainNameLen) < packetDataArray.Length)
                {                    
                    var tempArrayConversion = packetDataArray.Subsegment(Convert.ToInt32(DomainNameBufferOffset), DomainNameLen).ToArray();
                    DomainName = Encoding.Unicode.GetString(tempArrayConversion, 0, tempArrayConversion.Length);
                }

                if (UserNameLen > 0 && (UserNameBufferOffset + UserNameLen) < packetDataArray.Length)
                {
                    var tempArrayConversion = packetDataArray.Subsegment(Convert.ToInt32(UserNameBufferOffset), UserNameLen).ToArray();
                    UserName = Encoding.Unicode.GetString(tempArrayConversion, 0, tempArrayConversion.Length);
                }

                if (WorkstationLen > 0 && (WorkstationBufferOffset + WorkstationLen) < packetDataArray.Length)
                {
                    var tempArrayConversion = packetDataArray.Subsegment(Convert.ToInt32(WorkstationBufferOffset), WorkstationLen).ToArray();
                    Workstation = Encoding.Unicode.GetString(tempArrayConversion, 0, tempArrayConversion.Length);
                }

                if (EncryptedRandomSessionKeyLen > 0 && (EncryptedRandomSessionKeyBufferOffset + EncryptedRandomSessionKeyLen) < packetDataArray.Length)
                {
                    EncryptedRandomSessionKey = packetDataArray.Subsegment(Convert.ToInt32(EncryptedRandomSessionKeyBufferOffset), EncryptedRandomSessionKeyLen);
                }
                
                if (NtChallengeResponseLen == 24)
                {
                    Is_NTLMv2_Response = false;
                }

                if(NtChallengeResponse != null && Is_NTLMv2_Response && NtChallengeResponse.Length > 16)
                {
                    var Response = NtChallengeResponse.Subsegment(0, 16);
                    var NTLMv2_CLIENT_CHALLENGE = NtChallengeResponse.Subsegment(16, (NtChallengeResponse.Length - 16));

                    var NTLMv2_CLIENT_CHALLENGE_Array = NTLMv2_CLIENT_CHALLENGE.ToArray();
                    RespType = NTLMv2_CLIENT_CHALLENGE_Array.ReadByte(0);
                    HiRespType = NTLMv2_CLIENT_CHALLENGE_Array.ReadByte(1);

                    Reserved1 = NTLMv2_CLIENT_CHALLENGE_Array.ReadUShort(2, Endianity.Small);
                    Reserved2 = NTLMv2_CLIENT_CHALLENGE_Array.ReadUInt(4, Endianity.Small);
                    TimeStamp = NTLMv2_CLIENT_CHALLENGE_Array.ReadULong(8, Endianity.Small);
                    ChallengeFromClient = NTLMv2_CLIENT_CHALLENGE_Array.ReadULong(16, Endianity.Big);
                    Reserved3 = NTLMv2_CLIENT_CHALLENGE_Array.ReadUInt(24, Endianity.Small);

                    ParseAttributeValuePairs(NTLMv2_CLIENT_CHALLENGE_Array.Subsegment(28, (NTLMv2_CLIENT_CHALLENGE_Array.Length - 28)));
                }
                
            }
        }

        public class SESSION_SETUP_Response
        {
            private static class SESSION_SETUP_Response_Offsets
            {
                public const int StructureSize = 0;
                public const int SessionFlags = 2;
                public const int SecurityBufferOffset = 4;
                public const int SecurityBufferLength = 6;
                public const int Buffer = 8;
            }

            private DataSegment commandData = null;
            private DataSegment securityBuffer = null;

            public DataSegment CommandData
            {
                get
                {
                    return commandData;
                }
                set
                {
                    commandData = value;
                    ParseCommandData();
                }
            }
            public DataSegment SecurityBuffer
            {
                get
                {
                    return securityBuffer;
                }
                set
                {
                    securityBuffer = value;
                    ParseSecurityBuffer();
                }
            }
            public DataSegment NTLMSSPData = null;
            public ushort StructureSize = 0;
            public SESSION_SETUP_Response_Flag_Names SessionFlags = SESSION_SETUP_Response_Flag_Names.SMB2_SESSION_UNKNOWN;
            public NTLMSSP_MESSAGE NTLMSSPMessage = null;

            public ushort SecurityBufferOffset = 0;
            public ushort SecurityBufferLength = 0;

            public SESSION_SETUP_Response(DataSegment commandDataArg)
            {
                CommandData = commandDataArg;
            }

            private void ParseCommandData()
            {
                if(commandData == null)
                {
                    return;
                }

                if (commandData.Length <= 8)
                {
                    return;
                }

                var packetDataArray = commandData.ToArray();

                StructureSize = packetDataArray.ReadUShort(SESSION_SETUP_Response_Offsets.StructureSize, Endianity.Small);
                try
                {
                    SessionFlags = (SESSION_SETUP_Response_Flag_Names)packetDataArray.ReadUShort(SESSION_SETUP_Response_Offsets.SessionFlags, Endianity.Small);
                }
                catch
                {
                    SessionFlags = SESSION_SETUP_Response_Flag_Names.SMB2_SESSION_UNKNOWN;
                }
                
                SecurityBufferOffset = packetDataArray.ReadUShort(SESSION_SETUP_Response_Offsets.SecurityBufferOffset, Endianity.Small);
                SecurityBufferLength = packetDataArray.ReadUShort(SESSION_SETUP_Response_Offsets.SecurityBufferLength, Endianity.Small);
                SecurityBuffer = commandData.Subsegment(SESSION_SETUP_Response_Offsets.Buffer, (commandData.Length - SESSION_SETUP_Response_Offsets.Buffer));
            }
            
            private void ParseSecurityBuffer()
            {
                if (securityBuffer == null)
                {
                    return;
                }

                if (securityBuffer.Length <= 8)
                {
                    return;
                }

                var packetDataArray = securityBuffer.ToArray();
                int newOffset = packetDataArray.Find(0, packetDataArray.Length, NTLMSSPstring);

                if (newOffset < packetDataArray.Length)
                {
                    NTLMSSPData = securityBuffer.Subsegment(newOffset, (packetDataArray.Length - newOffset));

                    var NTLMSSPPacketType = NTLMSSPData.ToArray().ReadUInt(8, Endianity.Small);

                    if (NTLMSSPPacketType == 0x2)
                    {
                        NTLMSSPMessage = new NTLMSSP_CHALLENGE_MESSAGE(NTLMSSPData);
                    }
                    else if (NTLMSSPPacketType == 0x3)
                    {
                        NTLMSSPMessage = new NTLMSSP_AUTHENTICATE_MESSAGE(NTLMSSPData);
                    }
                }
            }
        }

        #region Private Variables
        private static class Offset
        {
            public const int ProtocolId = 0;
            public const int StructureSize = 4;
            public const int CreditCharge = 6;
            public const int Status = 8;
            public const int Command = 12;
            public const int CreditStatus = 14;
            public const int Flags = 16;
            public const int NextCommand = 20;
            public const int MessageId = 24;
            public const int ProcessId = 32;
            public const int TreeId = 36;
            public const int SessionId = 40;
            public const int Signature = 48;
            public const int CommandData = 64;
        }
        private static uint smb2_protocol_id = 4266872130;
        private static uint smb2_structure_size = 64;
        private DataSegment packetData = null;
        private SMB2CommandNames command = SMB2CommandNames.UNSET;
        private DataSegment commandData = null;
        private ushort creditCharge = 0;
        private ushort creditStatus = 0;
        private uint flags = 0;
        private ulong messageId = 0;
        private uint nextCommand = 0;
        private ulong processId = 0;
        private uint protocolId = 0;
        private DataSegment status = null;
        private ushort structureSize = 0;
        private uint treeId = 0;
        private ulong sessionId = 0;
        private DataSegment signature = null;
        #endregion

        #region Public Variables
        public SESSION_SETUP_Response SessionSetupResponse;
        public uint ProtocolId
        {
            get
            {
                return protocolId;
            }
            set
            {
                protocolId = value;
            }
        }
        public DataSegment Status
        {
            get
            {
                return status;
            }
            set
            {
                status = value;
            }
        }
        public ushort StructureSize
        {
            get
            {
                return structureSize;
            }
            set
            {
                if (value == 0x40)
                {
                    structureSize = value;
                }
                else
                {
                    structureSize = 0;
                }
            }
        }
        public ushort CreditCharge
        {
            get
            {
                return creditCharge;
            }
            set
            {
                creditCharge = value;
            }
        }
        public SMB2CommandNames Command
        {
            set
            {
                command = value;
            }
            get
            {
                return command;
            }
        }
        public DataSegment CommandData
        {
            get
            {
                return commandData;
            }
            set
            {
                commandData = value;
            }
        }
        public ushort CreditStatus
        {
            get
            {
                return creditStatus;
            }
            set
            {
                creditStatus = value;
            }
        }
        public uint Flags
        {
            get
            {
                return flags;
            }
            set
            {
                flags = value;
            }
        }
        public uint NextCommand
        {
            get
            {
                return nextCommand;
            }
            set
            {
                nextCommand = value;
            }
        }
        public ulong MessageId
        {
            get
            {
                return messageId;
            }
            set
            {
                messageId = value;
            }
        }
        public ulong ProcessId
        {
            get
            {
                return processId;
            }
            set
            {
                processId = value;
            }
        }
        public uint TreeId
        {
            get
            {
                return treeId;
            }
            set
            {
                treeId = value;
            }
        }
        public ulong SessionId
        {
            get
            {
                return sessionId;
            }
            set
            {
                sessionId = value;
            }
        }
        public DataSegment Signature
        {
            get
            {
                return signature;
            }
            set
            {
                signature = value;
            }
        }
        public DataSegment PacketData
        {
            get
            {
                return packetData;
            }
            set
            {
                packetData = value;
                ParsePacket();
            }
        }
        public bool IsValid
        {
            get
            {
                if(packetData != null && status != null && signature != null)
                {
                    return (command < SMB2CommandNames.UNSET && protocolId == smb2_protocol_id && structureSize > 0 && structureSize == smb2_structure_size);
                }
                else
                {
                    return false;
                }
            }
        }
        #endregion
        
        public SMB2Datagram(DataSegment dataSegment)
        {
            PacketData = dataSegment;
        }
        
        private void ParsePacket()
        {
            if (packetData.Length >= 64)
            {
                var packetDataArray = packetData.ToArray();

                ProtocolId = packetDataArray.ReadUInt(Offset.ProtocolId, Endianity.Big);
                StructureSize = packetDataArray.ReadUShort(Offset.StructureSize, Endianity.Small);
                CreditCharge = packetDataArray.ReadUShort(Offset.CreditCharge, Endianity.Small);
                Status = packetData.Subsegment(Offset.Status, 4);

                try
                {
                    Command = (SMB2CommandNames)packetDataArray.ReadUShort(Offset.Command, Endianity.Small);
                }
                catch
                {
                    Command = SMB2CommandNames.UNSET;
                }

                CreditStatus = packetDataArray.ReadUShort(Offset.CreditStatus, Endianity.Small);
                Flags = packetDataArray.ReadUInt(Offset.Flags, Endianity.Small);
                NextCommand = packetDataArray.ReadUInt(Offset.NextCommand, Endianity.Small);
                MessageId = packetDataArray.ReadULong(Offset.MessageId, Endianity.Small);
                ProcessId = packetDataArray.ReadULong(Offset.ProcessId, Endianity.Small);
                TreeId = packetDataArray.ReadUInt(Offset.TreeId, Endianity.Small);
                SessionId = packetDataArray.ReadULong(Offset.SessionId, Endianity.Small);
                Signature = packetData.Subsegment(Offset.Signature, 16);
            }
            if (packetData.Length > 64)
            {
                CommandData = packetData.Subsegment(Offset.CommandData, (packetData.Length - Offset.CommandData));
            }
            if(Command == SMB2CommandNames.SESSION_SETUP)
            {
                SessionSetupResponse = new SESSION_SETUP_Response(CommandData);
            }
        }
    }
}
