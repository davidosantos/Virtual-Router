/* 
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.DHCP;

import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author davidosantos
 */
public class DHCPPacket {

    private byte[] DHCPPacket;
    private ByteBuffer DHCPPacketByteBuffer;

    private final int Field_Op = 0;
    private final int Field_HType = 1;
    private final int Field_HLen = 2;
    private final int Field_Hops = 3;
    private final int Field_XID = 4;
    private final int Field_Secs = 8;
    private final int Field_Flags = 10;
    private final int Field_CIAddr = 12;
    private final int Field_YIAddr = 16;
    private final int Field_SIAddr = 20;
    private final int Field_GIAddr = 24;
    private final int Field_CHAddr = 28;
    private final int Field_SName = 45;
    private final int Field_File = 108;
    private final int Field_Options = 236;

    private int Index_Pointer_NewPacket = 240; // 4 apontará para primeira menssagem

    private final byte Ethernet10MB = 1;
    private final byte IEEE802Networks = 6;
    private final byte ARCNET = 7;
    private final byte LocalTalk = 11;
    private final byte LocalNet = 12;
    private final byte SMDS = 14;
    private final byte FrameRelay = 15;
    private final byte ATM = 16;
    private final byte HDLC = 17;
    private final byte FibreChannel = 18;
    private final byte ATM2 = 19;
    private final byte SerialLine = 20;

    private final int Field_DHCP_TheEnd = 255; // bytes depend on the name

    private final int OneByte = 1;
    private final int TwoBytes = 2;
    private final int FourBytes = 4;

    public final byte BOOTRequest = 1;
    public final byte BOOTReply = 2;

    public enum MessagesType {

        SubnetMask((byte) 1), //4           Subnet Mask Value                            [RFC2132]
        TimeOffset((byte) 2), //4           Time Offset in Seconds from UTC (note:       [RFC2132]    deprecated by 100 and 101)
        Router((byte) 3), //                                                   N           N/4 Router addresses                         [RFC2132]
        TimeServer((byte) 4), //                                              N           N/4 Timeserver addresses                     [RFC2132]
        NameServer((byte) 5), //                                              N           N/4 IEN-116 Server addresses                 [RFC2132]
        DNSServer((byte) 6),//                                             N           N/4 DNS Server addresses                     [RFC2132]
        LogServer((byte) 7),//                                                N           N/4 Logging Server addresses                 [RFC2132]
        QuotesServer((byte) 8),//                                             N           N/4 Quotes Server addresses                  [RFC2132]
        LPRServer((byte) 9),//                                                N           N/4 Printer Server addresses                 [RFC2132]
        ImpressServer((byte) 10),//                                          N           N/4 Impress Server addresses                 [RFC2132]
        RLPServer((byte) 11),//                                              N           N/4 RLP Server addresses                     [RFC2132]
        Hostname((byte) 12),//                                               N           Hostname string                              [RFC2132]
        BootFileSize((byte) 13),//                                           2           Size of boot file in 512 byte chunks         [RFC2132]
        MeritDumpFile((byte) 14),//                                         N           Client to dump and name the file to dump it  [RFC2132]
        DomainName((byte) 15),//                                              N           The DNS domain name of the client            [RFC2132]
        SwapServer((byte) 16),//                                           N           Swap Server address                          [RFC2132]
        RootPath((byte) 17),//                                               N           Path name for root disk                      [RFC2132]
        ExtensionFile((byte) 18),//                                          N           Path name for more BOOTP info                [RFC2132]
        ForwardOnOff((byte) 19),//                                           1           Enable/Disable IP Forwarding                 [RFC2132]
        SrcRteOnOff((byte) 20),//                                           1           Enable/Disable Source Routing                [RFC2132]
        PolicyFilter((byte) 21),//                                            N           Routing Policy Filters                       [RFC2132]
        MaxDGAssembly((byte) 22),//                                         2           Max Datagram Reassembly Size                 [RFC2132]
        DefaultIPTTL((byte) 23),//                                          1           Default IP Time to Live                      [RFC2132]
        MTUTimeout((byte) 24),//                                           4           Path MTU Aging Timeout                       [RFC2132]
        MTUPlateau((byte) 25),//                                            N           Path MTU Plateau Table                       [RFC2132]
        MTUInterface((byte) 26),//                                           2           Interface MTU Size                           [RFC2132]
        MTUSubnet((byte) 27),//                                           1           All Subnets are Local                        [RFC2132]
        BroadcastAddress((byte) 28),//                                       4           Broadcast Address                            [RFC2132]
        MaskDiscovery((byte) 29),//                                         1           Perform Mask Discovery                       [RFC2132]
        MaskSupplier((byte) 20),//                                          1           Provide Mask to Others                       [RFC2132]
        RouterDiscovery((byte) 31),//                                        1           Perform Router Discovery                     [RFC2132]
        RouterRequest((byte) 32),//                                        4           Router Solicitation Address                  [RFC2132]
        StaticRouteTable((byte) 33),//                                         N           Static Routing Table                         [RFC2132]
        Trailers((byte) 34),//                                         1           Trailer Encapsulation                        [RFC2132]
        ARPTimeout((byte) 35),//                                         4           ARP Cache Timeout                            [RFC2132]
        Ethernet((byte) 36),//                            1           Ethernet Encapsulation                       [RFC2132]
        DefaultTCPTTL((byte) 37),//                            1           Default TCP Time to Live                     [RFC2132]
        KeepaliveTime((byte) 38),//                            4           TCP Keepalive Interval                       [RFC2132]
        KeepaliveData((byte) 39),//                            1           TCP Keepalive Garbage                        [RFC2132]
        NISDomain((byte) 40),//                            N           NIS Domain Name                              [RFC2132]
        NISServers((byte) 41),//                            N           NIS Server Addresses                         [RFC2132]
        NTPServers((byte) 42),//                            N           NTP Server Addresses                         [RFC2132]
        VendorSpecific((byte) 43),//                            N           Vendor Specific Information                  [RFC2132]
        NETBIOSNameSrv((byte) 44),//                            N           NETBIOS Name Servers                         [RFC2132]
        NETBIOSDistSrv((byte) 45),//                            N           NETBIOS Datagram Distribution                [RFC2132]
        NETBIOSNodeType((byte) 46),//                            1           NETBIOS Node Type                            [RFC2132]
        NETBIOSScope((byte) 47),//                            N           NETBIOS Scope                                [RFC2132]
        XWindowFont((byte) 48),//                            N           X Window Font Server                         [RFC2132]
        XWindowManager((byte) 49),//                            N           X Window Display Manager                     [RFC2132]
        IPAddressRequested((byte) 50),//                            4           Requested IP Address                         [RFC2132]
        AddressLeaseTime((byte) 51),//                            4           IP Address Lease Time                        [RFC2132]
        Overload((byte) 52),//                            1           Overload "sname" or "file"                   [RFC2132]
        DHCPMsgType((byte) 53),//                            1           DHCP Message Type                            [RFC2132]
        DHCPServerId((byte) 54),//                            4           DHCP Server Identification                   [RFC2132]
        ParameterList((byte) 55),//                            N           Parameter Request List                       [RFC2132]
        DHCPErrorMessage((byte) 56),//                            N           DHCP Error Message                           [RFC2132]
        DHCPMaxMsgSize((byte) 57),//                            2           DHCP Maximum Message Size                    [RFC2132]
        RenewalTime((byte) 58),//                            4           DHCP Renewal (T1) Time                       [RFC2132]
        RebindingTime((byte) 59),//                            4           DHCP Rebinding (T2) Time                     [RFC2132]
        VendorClassIdentifier((byte) 60),//                            N           Class Identifier                             [RFC2132]
        ClientId((byte) 61),//                            N           Client Identifier                            [RFC2132]
        NetWare_IPDomain((byte) 62),//                            N           NetWare/IP Domain Name                       [RFC2242]
        NetWare_IPOption((byte) 63),//                            N           NetWare/IP sub Options                       [RFC2242]
        NISDomainName((byte) 64),//                            N           NIS+ v3 Client Domain Name                   [RFC2132]
        NISServerAddr((byte) 65),//                            N           NIS+ v3 Server Addresses                     [RFC2132]
        TFTPServerName((byte) 66),//                            N           TFTP Server Name                             [RFC2132]
        BootfileName((byte) 67),//                            N           Boot File Name                               [RFC2132]
        HomeAgentAddrs((byte) 68),//                            N           Home Agent Addresses                         [RFC2132]
        SMTPServer((byte) 69),//                            N           Simple Mail Server Addresses                 [RFC2132]
        POP3Server((byte) 70),//                            N           Post Office Server Addresses                 [RFC2132]
        NNTPServer((byte) 71),//                           N           Network News Server Addresses                [RFC2132]
        WWWServer((byte) 72),//                           N           WWW Server Addresses                         [RFC2132]
        FingerServer((byte) 73),//                           N           Finger Server Addresses                      [RFC2132]
        IRCServer((byte) 74),//              N           Chat Server Addresses                        [RFC2132]
        StreetTalkServer((byte) 75),//              N           StreetTalk Server Addresses                  [RFC2132]
        STDAServer((byte) 76),//              N           ST Directory Assist. Addresses               [RFC2132]
        UserClass((byte) 77),//              N           User Class Information                       [RFC3004]
        DirectoryAgent((byte) 78),//              N           directory agent information                  [RFC2610]
        ServiceScope((byte) 79),//              N           service location agent scope                 [RFC2610]
        RapidCommit((byte) 80),//              0           Rapid Commit                                 [RFC4039]
        ClientFQDN((byte) 81),//              N           Fully Qualified Domain Name                  [RFC4702]
        RelayAgentInformation((byte) 82),//              N           Relay Agent Information                      [RFC3046]
        iSNS((byte) 83),//              N           Internet Storage Name Service                [RFC4174]
        NDSServers((byte) 85),//              N           Novell Directory Services                    [RFC2241]
        NDSTreeName((byte) 86),//              N           Novell Directory Services                    [RFC2241]
        NDSContext((byte) 87),//              N           Novell Directory Services                    [RFC2241]
        BCMCSControllerDomainNamelist((byte) 88),//                                                                       [RFC4280]
        BCMCSControllerIPv4addressoption((byte) 89),//                                                                       [RFC4280]
        Authentication((byte) 90),//              N           Authentication                               [RFC3118]
        clientlasttransactiontimeoption((byte) 91),//                                                                       [RFC4388]
        ClientSystem((byte) 93),//              N           Client System Architecture                   [RFC4578]
        ClientNDI((byte) 94),//              N           Client Network Device Interface              [RFC4578]
        LDAP((byte) 95),//              N           Lightweight Directory Access Protocol        [RFC3679]
        UUIDGUID((byte) 97),//              N           UUID/GUID-based Client Identifier            [RFC4578]
        UserAuth((byte) 98),//              N           Open Group's User Authentication             [RFC2485]
        GEOCONF_CIVIC((byte) 99),//                                                                       [RFC4776]
        PCode((byte) 100),//              N           IEEE 1003.1 TZ String                        [RFC4833]
        TCode((byte) 101),//              N           Reference to the TZ Database                 [RFC4833]
        NetinfoAddress((byte) 112),//              N           NetInfo Parent Server Address                [RFC3679]
        NetinfoTag((byte) 113),//              N           NetInfo Parent Server Tag                    [RFC3679]
        URL((byte) 114),//              N           URL                                          [RFC3679]
        AutoConfig((byte) 116),//              N           DHCP Auto-Configuration                      [RFC2563]
        NameServiceSearch((byte) 117),//              N           Name Service Search                          [RFC2937]
        SubnetSelectionOption((byte) 118),//              4           Subnet Selection Option                      [RFC3011]
        DomainSearch((byte) 119),//              N           DNS domain search list                       [RFC3397]
        SIPServersDHCPOption((byte) 120),//              N           SIP Servers DHCP Option                      [RFC3361]
        ClasslessStaticRouteOption((byte) 121),//              N           Classless Static Route Option                [RFC3442]
        CCC((byte) 122),//              N           CableLabs Client Configuration               [RFC3495]
        GeoConfOption((byte) 123),//             16           GeoConf Option                               [RFC6225]
        VIVendorClass((byte) 124),//                           Vendor-Identifying Vendor Class              [RFC3925]
        VIVendorSpecificInformation((byte) 125),//              Vendor-Identifying Vendor-Specific Information          [RFC3925]
        dhcpstate((byte) 156),//                                               1           State of IP address.                         [RFC6926]
        datasource((byte) 157),//                                              1           Indicates information came from local or remote server Variable;
        RebootTime((byte) 211),//                                           4           Reboot Time                                  [RFC5071]
        OPTION_V4_ACCESS_DOMAIN((byte) 213),//                                N           Access Network Domain Name                   [RFC5986]
        SubnetAllocationOption((byte) 220),//                               N           Subnet Allocation Option                     [RFC6656]
        VirtualSubnetSelectionOption((byte) 221),//                                                                           [RFC6607]
        MicrosoftIPTable((byte) 249),//                                                                           
        TheEnd((byte) 255);

        private final byte mType;

        private MessagesType(byte mType) {
            this.mType = mType;

        }

        public byte getmType() {
            return mType;
        }

    }

    public enum NetBiosNodeTypes {

        Broadcast((byte) 1),
        Peer((byte) 2),
        Mixed((byte) 4),
        Hydrid((byte) 8);

        private final byte node;

        private NetBiosNodeTypes(byte node) {
            this.node = node;

        }

        public byte getNodeType() {
            return node;
        }

    }

    public enum DHCPMessagesType {

        DHCP_Discover((byte) 1),
        DHCP_Offer((byte) 2),
        DHCP_Request((byte) 3),
        DHCP_Decline((byte) 4),
        DHCP_PAck((byte) 5),
        DHCP_Nak((byte) 6),
        DHCP_Release((byte) 7),
        DHCP_Inform((byte) 8),
        DHCP_FORCE_RENEW((byte) 9),
        DHCP_LEASE_QUERY((byte) 10),
        DHCP_LEASE_UNASSIGNED((byte) 11),
        DHCP_LEASE_UNKNOWN((byte) 12),
        DHCP_LEASE_ACTIVE((byte) 13),
        DHCP_BULK_LEASE_QUERY((byte) 14),
        DHCP_LEASE_QUERY_DONE((byte) 15);
        private final byte Message;

        DHCPMessagesType(byte Message) {
            this.Message = Message;

        }

        public byte getMessageAsNumber() {
            return Message;
        }

    }

    public enum HType {

        Ethernet10MB((byte) 1),
        IEEE802Networks((byte) 6),
        ARCNET((byte) 7),
        LocalTalk((byte) 11),
        LocalNet((byte) 12),
        SMDS((byte) 14),
        FrameRelay((byte) 15),
        ATM((byte) 16),
        HDLC((byte) 17),
        FibreChannel((byte) 18),
        ATM2((byte) 19),
        SerialLine((byte) 19);

        private final byte hardwaretype;

        HType(byte htype) {
            this.hardwaretype = htype;

        }

        public byte getHType() {
            return hardwaretype;
        }

    }

    enum OP {

        Response((byte) 2),
        Request((byte) 1);
        private final byte op;

        public byte getOp() {
            return op;
        }

        OP(byte op) {
            this.op = op;

        }
    }

    DHCPPacket(OP Op, HType htype, InetAddress YIAddr, InetAddress SIAddr, InetAddress GIAddr, int xid) {
        DHCPPacket = new byte[1400];

        DHCPPacket[Field_HLen] = 6;
        DHCPPacket[Field_Hops] = 0;
        DHCPPacket[Field_Secs] = 0;
        DHCPPacket[Field_Flags] = 0;

        setOp(Op);
        setHType(htype);
        setYIAddr(YIAddr);
        //setSIAddr(SIAddr);
        //setGIAddr(GIAddr);
        setXID(xid);

    }

    DHCPPacket(DatagramPacket packet) {

        System.out.println("Packet size: " + packet.getLength());
        DHCPPacket = new byte[packet.getLength()];
        System.arraycopy(packet.getData(), 0, DHCPPacket, 0, packet.getLength());

    }

    /**
     * This method should be used when treating packet received from Network..
     * For creating this field look at createDHCPMessagesType
     *
     * @see createDHCPMessages
     *
     * @param type - Change the packet type to Discover, Offer so on ....
     */
    public final void setDHCPMessagesType(MessagesType type) {
        int Messaga_data = getMessageIndex(MessagesType.DHCPMsgType) + 2;
        DHCPPacket[Messaga_data] = type.getmType();
    }

    public final void createDHCPMessages(MessagesType type, DHCPMessagesType messageType) {
        DHCPPacket[Index_Pointer_NewPacket++] = type.getmType();
        DHCPPacket[Index_Pointer_NewPacket++] = OneByte;
        DHCPPacket[Index_Pointer_NewPacket++] = messageType.getMessageAsNumber();
    }

    /**
     * Useful with DHCP Parameters list option MessagesType.ParematersList.
     *
     * @param type
     * @param messageTypes
     */
    public final void createDHCPMessages(MessagesType type, MessagesType[] messageTypes) {
        DHCPPacket[Index_Pointer_NewPacket++] = type.getmType();
        DHCPPacket[Index_Pointer_NewPacket++] = (byte) (OneByte * messageTypes.length);
        for (MessagesType types : messageTypes) {
            DHCPPacket[Index_Pointer_NewPacket++] = types.getmType();
        }
    }

    public final void createDHCPMessages(MessagesType type) {
        DHCPPacket[Index_Pointer_NewPacket++] = type.getmType();
    }

    public final void createDHCPMessages(MessagesType type, boolean YesNo) {
        DHCPPacket[Index_Pointer_NewPacket++] = type.getmType();
        DHCPPacket[Index_Pointer_NewPacket++] = (byte) 1;
        if (YesNo) {
            DHCPPacket[Index_Pointer_NewPacket++] = (byte) 1;
        } else {
            DHCPPacket[Index_Pointer_NewPacket++] = (byte) 0;
        }
    }

    public final void createDHCPMessages(MessagesType type, Short bytes) {
        DHCPPacket[Index_Pointer_NewPacket++] = type.getmType();
        DHCPPacket[Index_Pointer_NewPacket++] = TwoBytes;
        byte[] bt = toBytes(bytes.intValue());
        DHCPPacket[Index_Pointer_NewPacket++] = bt[2]; //not sure if is right
        DHCPPacket[Index_Pointer_NewPacket++] = bt[3];

    }

    public final void createDHCPMessages(MessagesType type, NetBiosNodeTypes node) {
        DHCPPacket[Index_Pointer_NewPacket++] = type.getmType();
        DHCPPacket[Index_Pointer_NewPacket++] = OneByte;
        DHCPPacket[Index_Pointer_NewPacket++] = node.getNodeType();
    }

    public final void createDHCPMessages(MessagesType type, InetAddress ip) {
        DHCPPacket[Index_Pointer_NewPacket++] = type.getmType();
        DHCPPacket[Index_Pointer_NewPacket++] = FourBytes;
        DHCPPacket[Index_Pointer_NewPacket++] = ip.getAddress()[0];
        DHCPPacket[Index_Pointer_NewPacket++] = ip.getAddress()[1];
        DHCPPacket[Index_Pointer_NewPacket++] = ip.getAddress()[2];
        DHCPPacket[Index_Pointer_NewPacket++] = ip.getAddress()[3];
    }

    public final void createDHCPMessages(MessagesType type, InetAddress[] ips) {
        DHCPPacket[Index_Pointer_NewPacket++] = type.getmType();
        DHCPPacket[Index_Pointer_NewPacket++] = (byte) (ips.length * FourBytes);
        for (InetAddress inet : ips) {
            for (byte bt : inet.getAddress()) {
                DHCPPacket[Index_Pointer_NewPacket++] = bt;
            }
        }
    }

    public final void createDHCPMessages(MessagesType type, int time) {
        DHCPPacket[Index_Pointer_NewPacket++] = type.getmType();
        DHCPPacket[Index_Pointer_NewPacket++] = FourBytes;
        byte[] bytes;
        bytes = toBytes(time);
        DHCPPacket[Index_Pointer_NewPacket++] = bytes[0];
        DHCPPacket[Index_Pointer_NewPacket++] = bytes[1];
        DHCPPacket[Index_Pointer_NewPacket++] = bytes[2];
        DHCPPacket[Index_Pointer_NewPacket++] = bytes[3];
    }

    public final void createDHCPMessages(MessagesType type, String data) {
        DHCPPacket[Index_Pointer_NewPacket++] = type.getmType();
        DHCPPacket[Index_Pointer_NewPacket++] = (byte) data.length();
        for (byte bt : data.getBytes()) {
            DHCPPacket[Index_Pointer_NewPacket++] = bt;
        }
    }

    public final void createDHCPMessages(MessagesType type, byte[] data) {
        DHCPPacket[Index_Pointer_NewPacket++] = type.getmType();
        DHCPPacket[Index_Pointer_NewPacket++] = (byte) data.length;

        for (byte bt : data) {
            DHCPPacket[Index_Pointer_NewPacket++] = bt;
        }

    }

    public final void createMagicCookie() {
        int pointer = Field_Options;
        DHCPPacket[pointer++] = (byte) 0x63;
        DHCPPacket[pointer++] = (byte) 0x82;
        DHCPPacket[pointer++] = (byte) 0x53;
        DHCPPacket[pointer++] = (byte) 0x63;

    }

    public MessagesType messageNumbersToTypeName(int number) throws AssertionError {

        switch (number) {
            case 1:
                return MessagesType.SubnetMask;

            case 2:
                return MessagesType.TimeOffset;

            case 3:
                return MessagesType.Router;

            case 4:
                return MessagesType.TimeServer;

            case 5:
                return MessagesType.NameServer;

            case 6:
                return MessagesType.DNSServer;

            case 7:
                return MessagesType.LogServer;

            case 8:
                return MessagesType.QuotesServer;

            case 9:
                return MessagesType.LPRServer;

            case 10:
                return MessagesType.ImpressServer;

            case 11:
                return MessagesType.RLPServer;

            case 12:
                return MessagesType.Hostname;

            case 13:
                return MessagesType.BootFileSize;

            case 14:
                return MessagesType.MeritDumpFile;

            case 15:
                return MessagesType.DomainName;

            case 16:
                return MessagesType.SwapServer;

            case 17:
                return MessagesType.RootPath;

            case 18:
                return MessagesType.ExtensionFile;

            case 19:
                return MessagesType.ForwardOnOff;

            case 20:
                return MessagesType.SrcRteOnOff;

            case 21:
                return MessagesType.PolicyFilter;

            case 22:
                return MessagesType.MaxDGAssembly;

            case 23:
                return MessagesType.DefaultIPTTL;

            case 24:
                return MessagesType.MTUTimeout;

            case 25:
                return MessagesType.MTUPlateau;

            case 26:
                return MessagesType.MTUInterface;

            case 27:
                return MessagesType.MTUSubnet;

            case 28:
                return MessagesType.BroadcastAddress;

            case 29:
                return MessagesType.MaskDiscovery;

            case 30:
                return MessagesType.MaskSupplier;

            case 31:
                return MessagesType.RouterDiscovery;

            case 32:
                return MessagesType.RouterRequest;

            case 33:
                return MessagesType.StaticRouteTable;

            case 34:
                return MessagesType.Trailers;

            case 35:
                return MessagesType.ARPTimeout;

            case 36:
                return MessagesType.Ethernet;

            case 37:
                return MessagesType.DefaultTCPTTL;

            case 38:
                return MessagesType.KeepaliveTime;

            case 39:
                return MessagesType.KeepaliveData;

            case 40:
                return MessagesType.NISDomain;

            case 41:
                return MessagesType.NISServers;

            case 42:
                return MessagesType.NTPServers;

            case 43:
                return MessagesType.VendorSpecific;

            case 44:
                return MessagesType.NETBIOSNameSrv;

            case 45:
                return MessagesType.NETBIOSDistSrv;

            case 46:
                return MessagesType.NETBIOSNodeType;

            case 47:
                return MessagesType.NETBIOSScope;

            case 48:
                return MessagesType.XWindowFont;

            case 49:
                return MessagesType.XWindowManager;

            case 50:
                return MessagesType.IPAddressRequested;

            case 51:
                return MessagesType.AddressLeaseTime;

            case 52:
                return MessagesType.Overload;

            case 53:
                return MessagesType.DHCPMsgType;

            case 54:
                return MessagesType.DHCPServerId;

            case 55:
                return MessagesType.ParameterList;

            case 56:
                return MessagesType.DHCPErrorMessage;

            case 57:
                return MessagesType.DHCPMaxMsgSize;

            case 58:
                return MessagesType.RenewalTime;

            case 59:
                return MessagesType.RebindingTime;

            case 60:
                return MessagesType.VendorClassIdentifier;

            case 61:
                return MessagesType.ClientId;

            case 62:
                return MessagesType.NetWare_IPDomain;

            case 63:
                return MessagesType.NetWare_IPOption;

            case 64:
                return MessagesType.NISDomainName;

            case 65:
                return MessagesType.NISServerAddr;

            case 66:
                return MessagesType.TFTPServerName;

            case 67:
                return MessagesType.BootfileName;

            case 68:
                return MessagesType.HomeAgentAddrs;

            case 69:
                return MessagesType.SMTPServer;

            case 70:
                return MessagesType.POP3Server;

            case 71:
                return MessagesType.NNTPServer;

            case 72:
                return MessagesType.WWWServer;

            case 73:
                return MessagesType.FingerServer;

            case 74:
                return MessagesType.IRCServer;

            case 75:
                return MessagesType.StreetTalkServer;

            case 76:
                return MessagesType.STDAServer;

            case 77:
                return MessagesType.UserClass;

            case 78:
                return MessagesType.DirectoryAgent;

            case 79:
                return MessagesType.ServiceScope;

            case 80:
                return MessagesType.RapidCommit;

            case 81:
                return MessagesType.ClientFQDN;

            case 82:
                return MessagesType.RelayAgentInformation;

            case 83:
                return MessagesType.iSNS;

            case 84:
                return MessagesType.NDSServers;

            case 86:
                return MessagesType.NDSTreeName;

            case 87:
                return MessagesType.NDSContext;

            case 88:
                return MessagesType.BCMCSControllerDomainNamelist;

            case 89:
                return MessagesType.BCMCSControllerIPv4addressoption;

            case 90:
                return MessagesType.Authentication;

            case 91:
                return MessagesType.clientlasttransactiontimeoption;

            case 93:
                return MessagesType.ClientSystem;

            case 94:
                return MessagesType.ClientNDI;

            case 95:
                return MessagesType.LDAP;

            case 97:
                return MessagesType.UUIDGUID;

            case 98:
                return MessagesType.UserAuth;

            case 99:
                return MessagesType.GEOCONF_CIVIC;

            case 100:
                return MessagesType.PCode;

            case 101:
                return MessagesType.TCode;

            case 112:
                return MessagesType.NetinfoAddress;

            case 113:
                return MessagesType.NetinfoTag;

            case 114:
                return MessagesType.URL;

            case 116:
                return MessagesType.AutoConfig;

            case 117:
                return MessagesType.NameServiceSearch;

            case 118:
                return MessagesType.SubnetSelectionOption;

            case 119:
                return MessagesType.DomainSearch;

            case 120:
                return MessagesType.SIPServersDHCPOption;

            case 121:
                return MessagesType.ClasslessStaticRouteOption;

            case 122:
                return MessagesType.CCC;

            case 123:
                return MessagesType.GeoConfOption;

            case 124:
                return MessagesType.VIVendorClass;

            case 125:
                return MessagesType.VIVendorSpecificInformation;

            case 156:
                return MessagesType.dhcpstate;

            case 157:
                return MessagesType.datasource;

            case 211:
                return MessagesType.RebootTime;

            case 158:
                return MessagesType.OPTION_V4_ACCESS_DOMAIN;

            case 220:
                return MessagesType.SubnetAllocationOption;

            case 221:
                return MessagesType.VirtualSubnetSelectionOption;
            case 249:
                return MessagesType.MicrosoftIPTable;

            case 255:
                return MessagesType.TheEnd;

            default:
                throw new AssertionError("Could not find a message with number  " + number + ".");

        }

    }

    /**
     * This option is better not use, most of the clients uses 0, except windows
     * 7 but even windows 7 has a solution to this, it will retry and keep last
     * successful bit setting
     *
     * @return true if the client is expecting a broadcast or false if a
     * uni-cast
     */
    public boolean isBroadcast() {
        if (DHCPPacket[Field_Flags] == 1) {
            return true;
        } else if (DHCPPacket[Field_Flags] == 0) {
            return false;
        } else {
            throw new AssertionError("INVALID FLAGS");
        }
    }

    public void setSName(byte[] SName) {
        int counter = 0;
        for (byte caracter : SName) {
            DHCPPacket[Field_SName + counter] = caracter;
            counter++;
            if (counter > 64) {
                return;
            }
        }
    }

    public void setFile(byte[] file) {
        int counter = 0;
        for (byte caracter : file) {
            DHCPPacket[Field_File + counter] = caracter;
            counter++;
            if (counter > 128) {
                return;
            }
        }
    }

    public void setOptions(byte[] op) {
        int counter = 0;
        for (byte caracter : op) {
            DHCPPacket[Field_Options + counter] = caracter;
            counter++;
            if (counter > 64) {
                return;
            }
        }
    }

    public byte[] getCHAddr() {
        byte[] HAddr = new byte[16];
        HAddr[0] = DHCPPacket[Field_CHAddr + 0];
        HAddr[1] = DHCPPacket[Field_CHAddr + 1];
        HAddr[2] = DHCPPacket[Field_CHAddr + 2];
        HAddr[3] = DHCPPacket[Field_CHAddr + 3];
        HAddr[4] = DHCPPacket[Field_CHAddr + 4];
        HAddr[5] = DHCPPacket[Field_CHAddr + 5];
        HAddr[6] = DHCPPacket[Field_CHAddr + 6];
        HAddr[7] = DHCPPacket[Field_CHAddr + 7];
        HAddr[8] = DHCPPacket[Field_CHAddr + 8];
        HAddr[9] = DHCPPacket[Field_CHAddr + 9];
        HAddr[10] = DHCPPacket[Field_CHAddr + 10];
        HAddr[11] = DHCPPacket[Field_CHAddr + 11];
        HAddr[12] = DHCPPacket[Field_CHAddr + 12];
        HAddr[13] = DHCPPacket[Field_CHAddr + 13];
        HAddr[14] = DHCPPacket[Field_CHAddr + 14];
        HAddr[15] = DHCPPacket[Field_CHAddr + 15];

        return HAddr;
    }

    public void setCHAddr(byte[] HAddr) {
        DHCPPacket[Field_CHAddr] = HAddr[0];
        DHCPPacket[Field_CHAddr + 1] = HAddr[1];
        DHCPPacket[Field_CHAddr + 2] = HAddr[2];
        DHCPPacket[Field_CHAddr + 3] = HAddr[3];
        DHCPPacket[Field_CHAddr + 4] = HAddr[4];
        DHCPPacket[Field_CHAddr + 5] = HAddr[5];
        DHCPPacket[Field_CHAddr + 6] = HAddr[6];
        DHCPPacket[Field_CHAddr + 7] = HAddr[7];
        DHCPPacket[Field_CHAddr + 8] = HAddr[8];
        DHCPPacket[Field_CHAddr + 9] = HAddr[9];
        DHCPPacket[Field_CHAddr + 10] = HAddr[10];
        DHCPPacket[Field_CHAddr + 11] = HAddr[11];
        DHCPPacket[Field_CHAddr + 12] = HAddr[12];
        DHCPPacket[Field_CHAddr + 13] = HAddr[13];
        DHCPPacket[Field_CHAddr + 14] = HAddr[14];
        DHCPPacket[Field_CHAddr + 15] = HAddr[15];

    }

    public void setCIAddr(InetAddress inetAddres) {

        DHCPPacket[Field_CIAddr]
                = inetAddres.getAddress()[0];
        DHCPPacket[Field_CIAddr + 1]
                = inetAddres.getAddress()[1];
        DHCPPacket[Field_CIAddr + 2]
                = inetAddres.getAddress()[2];
        DHCPPacket[Field_CIAddr + 3]
                = inetAddres.getAddress()[3];

    }

    public final void setYIAddr(InetAddress inetAddres) {

        DHCPPacket[Field_YIAddr]
                = inetAddres.getAddress()[0];
        DHCPPacket[Field_YIAddr + 1]
                = inetAddres.getAddress()[1];
        DHCPPacket[Field_YIAddr + 2]
                = inetAddres.getAddress()[2];
        DHCPPacket[Field_YIAddr + 3]
                = inetAddres.getAddress()[3];
    }

    public final void setSIAddr(InetAddress inetAddres) {

        DHCPPacket[Field_SIAddr]
                = inetAddres.getAddress()[0];
        DHCPPacket[Field_SIAddr + 1]
                = inetAddres.getAddress()[1];
        DHCPPacket[Field_SIAddr + 2]
                = inetAddres.getAddress()[2];
        DHCPPacket[Field_SIAddr + 3]
                = inetAddres.getAddress()[3];
    }

    public final void setGIAddr(InetAddress inetAddres) {

        DHCPPacket[Field_GIAddr]
                = inetAddres.getAddress()[0];
        DHCPPacket[Field_GIAddr + 1]
                = inetAddres.getAddress()[1];
        DHCPPacket[Field_GIAddr + 2]
                = inetAddres.getAddress()[2];
        DHCPPacket[Field_GIAddr + 3]
                = inetAddres.getAddress()[3];
    }

    public final int getXID() {

        return ByteBuffer.wrap(DHCPPacket, Field_XID, FourBytes).getInt();

    }

    public final void setXID(int XID) {
        byte[] ByteArrey = toBytes(XID);
        DHCPPacket[Field_XID] = ByteArrey[0];
        DHCPPacket[Field_XID + 1] = ByteArrey[1];
        DHCPPacket[Field_XID + 2] = ByteArrey[2];
        DHCPPacket[Field_XID + 3] = ByteArrey[3];

    }

    private byte[] toBytes(int i) {
        byte[] result = new byte[4];

        result[0] = (byte) (i >> 24);
        result[1] = (byte) (i >> 16);
        result[2] = (byte) (i >> 8);
        result[3] = (byte) (i /*>> 0*/);

        return result;
    }

    public final void setOp(OP Op) {

        DHCPPacket[Field_Op] = Op.getOp();

    }

    public final void setHType(HType htype) {

        DHCPPacket[Field_HType] = htype.getHType();

    }

    @Override
    public String toString() {

        StringBuilder StrBuilder = new StringBuilder();

        if (DHCPPacket[Field_Op] == BOOTReply) {
            StrBuilder.append("Field_Op: BOOTReply \n");
        } else if (DHCPPacket[Field_Op] == BOOTRequest) {
            StrBuilder.append("Field_Op: BOOTRequest \n");
        } else {
            StrBuilder.append("Field_Op: Invalid \n");
        }

        switch (DHCPPacket[Field_HType]) {
            case Ethernet10MB:
                StrBuilder.append("Field_HType: Ethernet10MB\n");
                break;
            case IEEE802Networks:
                StrBuilder.append("Field_HType: IEEE802Networks\n");
                break;
            case ARCNET:
                StrBuilder.append("Field_HType: ARCNET\n");
                break;
            case LocalTalk:
                StrBuilder.append("Field_HType: LocalTalk\n");
                break;
            case LocalNet:
                StrBuilder.append("Field_HType: LocalNet\n");
                break;
            case SMDS:
                StrBuilder.append("Field_HType: SMDS\n");
                break;
            case FrameRelay:
                StrBuilder.append("Field_HType: FrameRelay\n");
                break;
            case ATM:
                StrBuilder.append("Field_HType: ATM\n");
                break;
            case HDLC:
                StrBuilder.append("Field_HType: HDLC\n");
                break;
            case FibreChannel:
                StrBuilder.append("Field_HType: FibreChannel\n");
                break;
            case ATM2:
                StrBuilder.append("Field_HType: ATM2\n");
                break;
            case SerialLine:
                StrBuilder.append("Field_HType: SerialLine\n");
                break;

            default:
                StrBuilder.append("Field_HType: Invalid\n");
        }

        StrBuilder.append("Field_HLen: ").append(DHCPPacket[Field_HLen] & 0xFF).append("\n");

        StrBuilder.append("Field_Hops: ").append(DHCPPacket[Field_Hops] & 0xFF).append("\n");

        StrBuilder.append("Field_XID: ").append("Transaction 0x").append(Integer.toHexString(getXID())).append("\n");

        ByteBuffer shrtSec = ByteBuffer.wrap(DHCPPacket, Field_Secs, TwoBytes);

        StrBuilder.append("Field_Secs: ").append(shrtSec.getShort() & 0xFF).append("\n");

        ByteBuffer shrt = ByteBuffer.wrap(DHCPPacket, Field_Flags, TwoBytes);

        StrBuilder.append("Field_Flags: ").append(shrt.getShort() & 0xFF).append("\n");

        StrBuilder.append("Field_CIAddr: ")
                .append(DHCPPacket[Field_CIAddr] & 0xFF).append(".")
                .append(DHCPPacket[Field_CIAddr + 1 & 0xFF]).append(".")
                .append(DHCPPacket[Field_CIAddr + 2] & 0xFF).append(".")
                .append(DHCPPacket[Field_CIAddr + 3] & 0xFF).append("\n");

        StrBuilder.append("Field_YIAddr: ")
                .append(DHCPPacket[Field_YIAddr] & 0xFF).append(".")
                .append(DHCPPacket[Field_YIAddr + 1] & 0xFF).append(".")
                .append(DHCPPacket[Field_YIAddr + 2] & 0xFF).append(".")
                .append(DHCPPacket[Field_YIAddr + 3] & 0xFF).append("\n");

        StrBuilder.append("Field_SIAddr: ")
                .append(DHCPPacket[Field_SIAddr] & 0xFF).append(".")
                .append(DHCPPacket[Field_SIAddr + 1] & 0xFF).append(".")
                .append(DHCPPacket[Field_SIAddr + 2] & 0xFF).append(".")
                .append(DHCPPacket[Field_SIAddr + 3] & 0xFF).append("\n");

        StrBuilder.append("Field_GIAddr: ")
                .append(DHCPPacket[Field_GIAddr] & 0xFF).append(".")
                .append(DHCPPacket[Field_GIAddr + 1] & 0xFF).append(".")
                .append(DHCPPacket[Field_GIAddr + 2] & 0xFF).append(".")
                .append(DHCPPacket[Field_GIAddr + 3] & 0xFF).append("\n");

        StrBuilder.append("Field_CHAddr: ");

        StrBuilder.append(String.format("%2s-%2s-%2s-%2s-%2s-%2s", Integer.toHexString(DHCPPacket[Field_CHAddr] & 0xFF).toUpperCase(), Integer.toHexString(DHCPPacket[Field_CHAddr + 1] & 0xFF).toUpperCase(), Integer.toHexString(DHCPPacket[Field_CHAddr + 2] & 0xFF).toUpperCase(), Integer.toHexString(DHCPPacket[Field_CHAddr + 3] & 0xFF).toUpperCase(), Integer.toHexString(DHCPPacket[Field_CHAddr + 4] & 0xFF).toUpperCase(), Integer.toHexString(DHCPPacket[Field_CHAddr + 5] & 0xFF).toUpperCase()));

        StrBuilder.append("\n");
        StrBuilder.append("Field_SName: ");
        String Field_SN = new String(DHCPPacket, Field_SName, 64);
        StrBuilder.append(Field_SN.toCharArray());

        StrBuilder.append("\n");
        StrBuilder.append("File: ");
        String Field_Fil = new String(DHCPPacket, Field_File, 128);
        StrBuilder.append(Field_Fil.toCharArray());

        StrBuilder.append("\n");
        StrBuilder.append("DHCP Options: ");
        StrBuilder.append("Magic Cookie: ").append(Integer.toHexString(ByteBuffer.wrap(DHCPPacket, Field_Options, FourBytes).getInt())).append("\n");

        StrBuilder.append(getOptionsString());

        return StrBuilder.toString();

    }

    private byte[] getDHCPMessage(int offset, int length) {

        byte[] data = new byte[length];

        for (int i = 0; i < length; i++) {
            data[i] = (byte) (DHCPPacket[offset + i] & 0xFF);
        }

        return data;
    }

    public byte getMessageNumber(MessagesType type) {
        return type.getmType();
    }

    public byte[] getMessageBytes(MessagesType type) throws AssertionError {
        int Index_Pointer = Field_Options + FourBytes; // + 4 porque Field_Options aponta para o Magic Cookie, então mais 4 apontará para primeira menssagem
        int Message_number = (DHCPPacket[Index_Pointer] & 0xFF); //primeira msg
        int Message_Length;
        int MessageType_Number = type.getmType();

        while (Index_Pointer < DHCPPacket.length - 1) {
            if (Message_number == Field_DHCP_TheEnd) {
                throw new AssertionError("05 End of Messages Reached, could not find message: " + type.toString());
            }

            Message_number = (DHCPPacket[Index_Pointer] & 0xFF);
            Message_Length = (DHCPPacket[Index_Pointer + OneByte] & 0xFF);

            if (Message_number == MessageType_Number) {
                byte[] bytes = new byte[Message_Length];
                Index_Pointer += TwoBytes; //points to first data of message
                for (int i = 0; i < Message_Length; i++) {
                    bytes[i] = DHCPPacket[Index_Pointer + i];
                }

                return bytes;
            }
            Index_Pointer += ((DHCPPacket[Index_Pointer + OneByte] & 0xFF) + 2); //apontará para proxima msg

        }

        throw new AssertionError("01 End of Messages Reached, could not find message: " + type.toString());
    }

    public int getMessageOffset(MessagesType type) throws AssertionError {
        int Index_Pointer = Field_Options + FourBytes; // + 4 porque Field_Options aponta para o Magic Cookie, então mais 4 apontará para primeira menssagem
        int Message_number = (DHCPPacket[Index_Pointer] & 0xFF); //primeira msg
        int MessageType_Number = type.getmType();

        while (Index_Pointer < DHCPPacket.length - 1) {
            if (Message_number == Field_DHCP_TheEnd) {
                return Index_Pointer;
            }

            Message_number = (DHCPPacket[Index_Pointer] & 0xFF);

            if (Message_number == MessageType_Number) {

                return Index_Pointer;
            }
            Index_Pointer += ((DHCPPacket[Index_Pointer + OneByte] & 0xFF) + 2); //apontará para proxima msg

        }

        throw new AssertionError("02 End of Messages Reached, could not find message: " + type.toString());
    }

    public List<Integer> getAllPacketMessageNumbers() throws AssertionError {
        int Index_Pointer = Field_Options + FourBytes; // + 4 porque Field_Options aponta para o Magic Cookie, então mais 4 apontará para primeira menssagem
        int Message_number = (DHCPPacket[Index_Pointer] & 0xFF); //primeira msg
        List<Integer> Numbers = new ArrayList<>();

        while (Index_Pointer < DHCPPacket.length - 1) {

            Numbers.add(Message_number);

            if (Message_number == Field_DHCP_TheEnd) {

                return Numbers;
            }

            Index_Pointer += ((DHCPPacket[Index_Pointer + OneByte] & 0xFF) + 2); //apontará para proxima msg
            Message_number = (DHCPPacket[Index_Pointer] & 0xFF);
        }

        return Numbers;
    }

    public int getMessageIndex(MessagesType type) throws AssertionError {
        int Index_Pointer = Field_Options + FourBytes; // + 4 porque Field_Options aponta para o Magic Cookie, então mais 4 apontará para primeira menssagem
        int Message_number = (DHCPPacket[Index_Pointer] & 0xFF); //primeira msg
        int MessageType_Number = type.getmType();

        while (Index_Pointer < DHCPPacket.length - 1) {
            if (Message_number == Field_DHCP_TheEnd) {
                throw new AssertionError("03 End of Messages Reached, could not find message: " + type.toString());
            }

            Message_number = (DHCPPacket[Index_Pointer] & 0xFF);

            if (Message_number == MessageType_Number) {

                return Index_Pointer;
            }
            Index_Pointer += ((DHCPPacket[Index_Pointer + OneByte] & 0xFF) + 2); //apontará para proxima msg

        }
        throw new AssertionError("04 End of Messages Reached, could not find message: " + type.toString());
    }

    public boolean isMessageExist(MessagesType type) throws AssertionError {
        int Index_Pointer = Field_Options + FourBytes; // + 4 porque Field_Options aponta para o Magic Cookie, então mais 4 apontará para primeira menssagem
        int Message_number;
        int MessageType_Number = type.getmType();

        while (Index_Pointer < DHCPPacket.length - 1) {

            Message_number = (DHCPPacket[Index_Pointer] & 0xFF);

            if (Message_number == MessageType_Number) {

                return true;
            }
            Index_Pointer += ((DHCPPacket[Index_Pointer + OneByte] & 0xFF) + 2); //apontará para proxima msg

        }
        return false;
    }

    public String getOptionsString() {
        int Message_number;
        int Message_Length;
        int Message_Data;
        StringBuilder str = new StringBuilder();

        int Index_Pointer = Field_Options + FourBytes; // + 4 porque Field_Options aponta para o Magic Cookie, então mais 4 apontará para primeira menssagem

        while (Index_Pointer < DHCPPacket.length - 1) {

            Message_number = (DHCPPacket[Index_Pointer] & 0xFF);

            if (Message_number == Field_DHCP_TheEnd) {
                return str.toString();
            }
            Message_Length = (DHCPPacket[Index_Pointer + OneByte] & 0xFF);
            Message_Data = (Index_Pointer + TwoBytes);

            str.append("Message Number/Name: ").append(messageNumbersToTypeName(Message_number).toString()).append(" index: ").append(Index_Pointer).append(" length: ").append(Message_Length).append(" Message data: ").append(new String(getDHCPMessage(Message_Data, Message_Length))).append("\n");
            if (Message_number == getMessageNumber(MessagesType.DHCPMsgType)) {
                if (getMessageBytes(MessagesType.DHCPMsgType)[0] == DHCPMessagesType.DHCP_Discover.getMessageAsNumber()) {
                    str.append(DHCPMessagesType.DHCP_Discover.toString()).append("\n");
                }
                if (getMessageBytes(MessagesType.DHCPMsgType)[0] == DHCPMessagesType.DHCP_Request.getMessageAsNumber()) {
                    str.append(DHCPMessagesType.DHCP_Request.toString()).append("\n");
                }
                if (getMessageBytes(MessagesType.DHCPMsgType)[0] == DHCPMessagesType.DHCP_Offer.getMessageAsNumber()) {
                    str.append(DHCPMessagesType.DHCP_Offer.toString()).append("\n");
                }
                if (getMessageBytes(MessagesType.DHCPMsgType)[0] == DHCPMessagesType.DHCP_PAck.getMessageAsNumber()) {
                    str.append(DHCPMessagesType.DHCP_PAck.toString()).append("\n");
                }
                if (getMessageBytes(MessagesType.DHCPMsgType)[0] == DHCPMessagesType.DHCP_Release.getMessageAsNumber()) {
                    str.append(DHCPMessagesType.DHCP_Release.toString()).append("\n");
                }
                if (getMessageBytes(MessagesType.DHCPMsgType)[0] == DHCPMessagesType.DHCP_Nak.getMessageAsNumber()) {
                    str.append(DHCPMessagesType.DHCP_Nak.toString()).append("\n");
                }
                if (getMessageBytes(MessagesType.DHCPMsgType)[0] == DHCPMessagesType.DHCP_Inform.getMessageAsNumber()) {
                    str.append(DHCPMessagesType.DHCP_Inform.toString()).append("\n");
                }
                if (getMessageBytes(MessagesType.DHCPMsgType)[0] == DHCPMessagesType.DHCP_Decline.getMessageAsNumber()) {
                    str.append(DHCPMessagesType.DHCP_Decline.toString()).append("\n");
                }
                if (getMessageBytes(MessagesType.DHCPMsgType)[0] == DHCPMessagesType.DHCP_LEASE_ACTIVE.getMessageAsNumber()) {
                    str.append(DHCPMessagesType.DHCP_LEASE_ACTIVE.toString()).append("\n");
                }
                if (getMessageBytes(MessagesType.DHCPMsgType)[0] == DHCPMessagesType.DHCP_LEASE_QUERY.getMessageAsNumber()) {
                    str.append(DHCPMessagesType.DHCP_LEASE_QUERY.toString()).append("\n");
                }
                if (getMessageBytes(MessagesType.DHCPMsgType)[0] == DHCPMessagesType.DHCP_LEASE_UNASSIGNED.getMessageAsNumber()) {
                    str.append(DHCPMessagesType.DHCP_LEASE_UNASSIGNED.toString()).append("\n");
                }
                if (getMessageBytes(MessagesType.DHCPMsgType)[0] == DHCPMessagesType.DHCP_LEASE_QUERY_DONE.getMessageAsNumber()) {
                    str.append(DHCPMessagesType.DHCP_LEASE_QUERY_DONE.toString()).append("\n");
                }
                if (getMessageBytes(MessagesType.DHCPMsgType)[0] == DHCPMessagesType.DHCP_FORCE_RENEW.getMessageAsNumber()) {
                    str.append(DHCPMessagesType.DHCP_FORCE_RENEW.toString()).append("\n");
                }
                if (getMessageBytes(MessagesType.DHCPMsgType)[0] == DHCPMessagesType.DHCP_BULK_LEASE_QUERY.getMessageAsNumber()) {
                    str.append(DHCPMessagesType.DHCP_BULK_LEASE_QUERY.toString()).append("\n");
                }

            }
            Index_Pointer += ((DHCPPacket[Index_Pointer + OneByte] & 0xFF) + 2); //apontará para proxima msg

        }

        return str.toString();
    }

    public String getMACAddrs() {

        return String.format("%2s-%2s-%2s-%2s-%2s-%2s",
                Integer.toHexString(DHCPPacket[Field_CHAddr] & 0xFF).toUpperCase(),
                Integer.toHexString(DHCPPacket[Field_CHAddr + 1] & 0xFF).toUpperCase(),
                Integer.toHexString(DHCPPacket[Field_CHAddr + 2] & 0xFF).toUpperCase(),
                Integer.toHexString(DHCPPacket[Field_CHAddr + 3] & 0xFF).toUpperCase(),
                Integer.toHexString(DHCPPacket[Field_CHAddr + 4] & 0xFF).toUpperCase(),
                Integer.toHexString(DHCPPacket[Field_CHAddr + 5] & 0xFF).toUpperCase());

    }

    public String getCIAddr() {
        StringBuilder StrBuilder = new StringBuilder();
        return StrBuilder
                .append(DHCPPacket[Field_CIAddr] & 0xFF).append(".")
                .append(DHCPPacket[Field_CIAddr + 1] & 0xFF).append(".")
                .append(DHCPPacket[Field_CIAddr + 2] & 0xFF).append(".")
                .append(DHCPPacket[Field_CIAddr + 3] & 0xFF).toString();
    }

    public String getYIAddr() {
        StringBuilder StrBuilder = new StringBuilder();
        return StrBuilder
                .append(DHCPPacket[Field_YIAddr] & 0xFF).append(".")
                .append(DHCPPacket[Field_YIAddr + 1] & 0xFF).append(".")
                .append(DHCPPacket[Field_YIAddr + 2] & 0xFF).append(".")
                .append(DHCPPacket[Field_YIAddr + 3] & 0xFF).toString();
    }

    public DatagramPacket getPacket() {

        int MsgSize = getMessageOffset(MessagesType.TheEnd);

        DHCPPacketByteBuffer = ByteBuffer.wrap(DHCPPacket, 0, MsgSize + 1);
        DHCPPacketByteBuffer.order(ByteOrder.BIG_ENDIAN);
        DatagramPacket packet = new DatagramPacket(DHCPPacketByteBuffer.array(), MsgSize + 1);

        return packet;
    }

}
