/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package DavidSantos.VirtualRouter.DHCP;

import DavidSantos.VirtualRouter.Ports.Ports;
import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

/**
 *
 * @author dsantos4
 */
public class DHCPTransaction extends Thread {

    private DHCPPacket DhcpPacket_Received;
    private DHCPPacket DhcpPacket_Reply;
    private final int Transaction_Id;
    private final boolean PermanemtlyStart;

    private static int TheadsCount = 0;

    public synchronized static int getTheadsCount() {
        return TheadsCount;
    }

    public synchronized static void IncTheadsCount() {
        TheadsCount++;
    }

    public synchronized static void DecTheadsCount() {
        TheadsCount--;
    }

    private final DHCPImplementation DHCPImpl;

    public int getTransaction_Id() {
        return Transaction_Id;
    }

    public DHCPTransaction(DHCPPacket packet, int Transaction_Id, DHCPImplementation Impl) throws SocketException {

        DhcpPacket_Received = packet;
        this.Transaction_Id = Transaction_Id;
        this.PermanemtlyStart = false;
        this.setName("Transaction 0x" + Integer.toHexString(this.Transaction_Id));
        this.DHCPImpl = Impl;
        IncTheadsCount();
    }

    public DHCPTransaction(DHCPImplementation Impl) throws SocketException, IOException {
        this.PermanemtlyStart = true;
        this.setName("DHCP Transaction Permanent");
        this.Transaction_Id = 0;
        this.DHCPImpl = Impl;
    }

    @Override
    public void run() {

        if (PermanemtlyStart) {

            do {
                try {
                    if (getTheadsCount() < 1) { // listen to that port only if no more threads are using it
                        DhcpPacket_Received = new DHCPPacket(Ports.receiveDHCPData(Ports.Timeout.Permanently, Ports.PortsNumber.Port_DHCP_Receive));
                        DHCPImpl.onDHCPPackageReceived(DhcpPacket_Received);
                        DHCPTransaction dhcpTransaction = new DHCPTransaction(DhcpPacket_Received, DhcpPacket_Received.getXID(), DHCPImpl);
                        dhcpTransaction.start();
                    }
                    //Thread.sleep(10000); //sleep for ten sec so that the other Thead catches the port
                } catch (IOException ex) {
                    //  DHCPImpl.onIOException(ex);
                }

            } while (true);

        } else {

            try {
                while (true) {

                    DhcpPacket_Reply = getPreparedDHCPPacket();
                    if (DhcpPacket_Reply == null) {
                        return;
                    }

                    //if(DhcpPacket_Received.isBroadcast()){
                    Ports.sendDHCPData(DhcpPacket_Reply.getPacket(), Ports.PortsNumber.Port_DHCP_Receive, InetAddress.getByName("255.255.255.255"), Ports.PortsNumber.Port_DHCP_Reply);
                    //         } else {
                    // Ports.sendDHCPData(DhcpPacket_Reply.getPacket(), Ports.PortsNumber.Port_DHCP_Receive, InetAddress.getByAddress(DhcpPacket_Received.getMessageBytes(DHCPPacket.MessagesType.IPAddressRequested)), Ports.PortsNumber.Port_DHCP_Reply);
                    //       }
                    DHCPImpl.onDHCPPackageSent(DhcpPacket_Reply);
                    if (DhcpPacket_Reply.getMessageBytes(DHCPPacket.MessagesType.DHCPMsgType)[0] == DHCPPacket.DHCPMessagesType.DHCP_PAck.getMessageAsNumber()) {
                        DHCPImpl.onIPacknowledged(DhcpPacket_Reply.getYIAddr());
                    }
                    do { //respond only to the right transaction
                        DhcpPacket_Received = new DHCPPacket(Ports.receiveDHCPData(Ports.Timeout.FiveSecs, Ports.PortsNumber.Port_DHCP_Receive)); // time out exception exits the loop
                        DHCPImpl.onDHCPPackageReceived(DhcpPacket_Received);
                        /* problematic code
                         if (DhcpPacket_Received.getXID() != this.Transaction_Id) { //if it is another transaction, just create a new thread to deal with it
                         DHCPTransaction dhcpTransaction = new DHCPTransaction(DhcpPacket_Received, DhcpPacket_Received.getXID(), DHCPImpl);
                         dhcpTransaction.start();
                         } */
                    } while (DhcpPacket_Received.getXID() != this.Transaction_Id); //if packet recieved differ so try again and wait ten secs

                }

            } catch (IOException ex) {
                System.out.println("Exiting Thread: " + this.getName() + ex.getMessage());

                DHCPImpl.onIOException(ex);

            } catch (AssertionError ex) {
                System.out.println("Exiting Thread: " + this.getName() + ex.getMessage());

                DHCPImpl.onAssertionError(ex);
            }
            DecTheadsCount();
        }

    }

    private DHCPPacket getPreparedDHCPPacket() throws UnknownHostException, AssertionError { //by default create a offer packet
        boolean isIpRequestedPermited = true;
        try {
            DHCPPacket Reply = new DHCPPacket(DHCPPacket.OP.Response, DHCPPacket.HType.Ethernet10MB,
                    InetAddress.getByName(DHCPImpl.getNextAvlIP()), //Next Available Ip
InetAddress.getByName(DHCPImpl.getServerIP()), // Server IP
InetAddress.getByName(DHCPImpl.getDefaultGatewayIP()), //Gateway
                    DhcpPacket_Received.getXID());

            Reply.createMagicCookie();
            Reply.setCHAddr(DhcpPacket_Received.getCHAddr());

            if (DhcpPacket_Received.isMessageExist(DHCPPacket.MessagesType.IPAddressRequested)) {
                isIpRequestedPermited = DHCPImpl.IPAddressRequest(
                        new String(DhcpPacket_Received.getMessageBytes(DHCPPacket.MessagesType.IPAddressRequested)),
                        DhcpPacket_Received.getMACAddrs(),
                        new String(DhcpPacket_Received.getMessageBytes(DHCPPacket.MessagesType.Hostname)));
            }

            /*DHCP Options: Magic Cookie: 63825363
             Message Number/Name: DHCPMsgType index: 240 length: 1 Message data: 
             Message Number/Name: AutoConfig index: 243 length: 1 Message data: 
             Message Number/Name: ClientId index: 246 length: 7 Message data: #C�
             Message Number/Name: Hostname index: 255 length: 15 Message data: david-2777f485f
             Message Number/Name: VendorClassIdentifier index: 272 length: 8 Message data: MSFT 5.0
             Message Number/Name: ParameterList index: 282 length: 11 Message data: ,./!�
             Message Number/Name: VendorSpecific index: 295 length: 2 Message data: � */
            if (DhcpPacket_Received.getMessageBytes(DHCPPacket.MessagesType.DHCPMsgType)[0]
                    == DHCPPacket.DHCPMessagesType.DHCP_Discover.getMessageAsNumber()) {

                Reply.createDHCPMessages(DHCPPacket.MessagesType.DHCPMsgType, DHCPPacket.DHCPMessagesType.DHCP_Offer);

            } else if (DhcpPacket_Received.getMessageBytes(DHCPPacket.MessagesType.DHCPMsgType)[0]
                    == DHCPPacket.DHCPMessagesType.DHCP_Offer.getMessageAsNumber()) {
            } else if (DhcpPacket_Received.getMessageBytes(DHCPPacket.MessagesType.DHCPMsgType)[0]
                    == DHCPPacket.DHCPMessagesType.DHCP_Request.getMessageAsNumber()) {
                if (isIpRequestedPermited) {
                    Reply.createDHCPMessages(DHCPPacket.MessagesType.DHCPMsgType, DHCPPacket.DHCPMessagesType.DHCP_PAck);
                } else {
                    Reply.createDHCPMessages(DHCPPacket.MessagesType.DHCPMsgType, DHCPPacket.DHCPMessagesType.DHCP_Nak);
                }
            } else if (DhcpPacket_Received.getMessageBytes(DHCPPacket.MessagesType.DHCPMsgType)[0]
                    == DHCPPacket.DHCPMessagesType.DHCP_Decline.getMessageAsNumber()) {
            } else if (DhcpPacket_Received.getMessageBytes(DHCPPacket.MessagesType.DHCPMsgType)[0]
                    == DHCPPacket.DHCPMessagesType.DHCP_PAck.getMessageAsNumber()) {
            } else if (DhcpPacket_Received.getMessageBytes(DHCPPacket.MessagesType.DHCPMsgType)[0]
                    == DHCPPacket.DHCPMessagesType.DHCP_Nak.getMessageAsNumber()) {
            } else if (DhcpPacket_Received.getMessageBytes(DHCPPacket.MessagesType.DHCPMsgType)[0]
                    == DHCPPacket.DHCPMessagesType.DHCP_Release.getMessageAsNumber()) {
            } else if (DhcpPacket_Received.getMessageBytes(DHCPPacket.MessagesType.DHCPMsgType)[0]
                    == DHCPPacket.DHCPMessagesType.DHCP_Inform.getMessageAsNumber()) {
            } else if (DhcpPacket_Received.getMessageBytes(DHCPPacket.MessagesType.DHCPMsgType)[0]
                    == DHCPPacket.DHCPMessagesType.DHCP_FORCE_RENEW.getMessageAsNumber()) {
            } else if (DhcpPacket_Received.getMessageBytes(DHCPPacket.MessagesType.DHCPMsgType)[0]
                    == DHCPPacket.DHCPMessagesType.DHCP_LEASE_QUERY.getMessageAsNumber()) {
            } else if (DhcpPacket_Received.getMessageBytes(DHCPPacket.MessagesType.DHCPMsgType)[0]
                    == DHCPPacket.DHCPMessagesType.DHCP_LEASE_UNASSIGNED.getMessageAsNumber()) {
            } else if (DhcpPacket_Received.getMessageBytes(DHCPPacket.MessagesType.DHCPMsgType)[0]
                    == DHCPPacket.DHCPMessagesType.DHCP_LEASE_UNKNOWN.getMessageAsNumber()) {
            } else if (DhcpPacket_Received.getMessageBytes(DHCPPacket.MessagesType.DHCPMsgType)[0]
                    == DHCPPacket.DHCPMessagesType.DHCP_LEASE_ACTIVE.getMessageAsNumber()) {
            } else if (DhcpPacket_Received.getMessageBytes(DHCPPacket.MessagesType.DHCPMsgType)[0]
                    == DHCPPacket.DHCPMessagesType.DHCP_BULK_LEASE_QUERY.getMessageAsNumber()) {
            } else if (DhcpPacket_Received.getMessageBytes(DHCPPacket.MessagesType.DHCPMsgType)[0]
                    == DHCPPacket.DHCPMessagesType.DHCP_LEASE_QUERY_DONE.getMessageAsNumber()) {

            } else {
                throw new AssertionError("Message unkown from message 53 first message: " + DhcpPacket_Received.getMessageBytes(DHCPPacket.MessagesType.DHCPMsgType)[0]);
            }

            Reply.createDHCPMessages(DHCPPacket.MessagesType.SubnetMask, InetAddress.getByName(DHCPImpl.getMaskIP()));
            Reply.createDHCPMessages(DHCPPacket.MessagesType.DHCPServerId, InetAddress.getByName(DHCPImpl.getDHCPServerIP()));

            //parametere list
            try {
                for (byte bt : DhcpPacket_Received.getMessageBytes(DHCPPacket.MessagesType.ParameterList)) {

                    proccessMessges(Reply, DhcpPacket_Received.messageNumbersToTypeName(bt & 0xFF));
                }
            } catch (AssertionError error) {
                DHCPImpl.onAssertionError(error);
            }

            Reply.createDHCPMessages(DHCPPacket.MessagesType.RenewalTime, DHCPImpl.getRenewalTime());
            Reply.createDHCPMessages(DHCPPacket.MessagesType.RebindingTime, DHCPImpl.getRebindingTime());
            Reply.createDHCPMessages(DHCPPacket.MessagesType.AddressLeaseTime, DHCPImpl.getAddressLeaseTime());
            Reply.createDHCPMessages(DHCPPacket.MessagesType.AutoConfig, false);
            Reply.createDHCPMessages(DHCPPacket.MessagesType.TheEnd);

            return Reply;
        } catch (UnknownHostException ex) {
            DHCPImpl.onUnknownHostException(ex);
        }
        return null;
    }

    private void proccessMessges(DHCPPacket Reply, DHCPPacket.MessagesType type) throws UnknownHostException {
        switch (type) {
            case SubnetMask:

                Reply.createDHCPMessages(DHCPPacket.MessagesType.SubnetMask, InetAddress.getByName(DHCPImpl.getMaskIP()));

                break;
            case TimeOffset:

                int time = DHCPImpl.getTimeOffset();

                Reply.createDHCPMessages(DHCPPacket.MessagesType.TimeOffset, time);

                break;
            case Router:
                Reply.createDHCPMessages(DHCPPacket.MessagesType.Router, InetAddress.getByName(DHCPImpl.getDefaultRouterIP()));
                break;
            case TimeServer:

                Reply.createDHCPMessages(DHCPPacket.MessagesType.TimeServer, InetAddress.getByName(DHCPImpl.getTimeServer()));

                break;
            case NameServer:

                String[] NameServer = DHCPImpl.getNameServers();

                if (NameServer != null) {
                    InetAddress inetName[] = new InetAddress[NameServer.length];

                    for (int i = 0; i < NameServer.length; i++) {
                        inetName[i] = InetAddress.getByName(NameServer[i]);
                    }

                    Reply.createDHCPMessages(DHCPPacket.MessagesType.NameServer, inetName);
                }
                break;
            case DNSServer:

                String[] DNServer = DHCPImpl.getDNSServers();

                if (DNServer != null) {
                    InetAddress inetDNS[] = new InetAddress[DNServer.length];

                    for (int i = 0; i < DNServer.length; i++) {
                        inetDNS[i] = InetAddress.getByName(DNServer[i]);
                    }

                    Reply.createDHCPMessages(DHCPPacket.MessagesType.DNSServer, inetDNS);
                }
                break;
            case LogServer:

                break;
            case QuotesServer:
                break;
            case LPRServer:
                break;
            case ImpressServer:
                break;
            case RLPServer:
                break;
            case Hostname:
                break;
            case BootFileSize:
                break;
            case MeritDumpFile:
                break;
            case DomainName:

                String domainName = DHCPImpl.getDomainName();
                if (domainName != null) {
                    Reply.createDHCPMessages(DHCPPacket.MessagesType.DomainName, domainName);
                }

                break;
            case SwapServer:
                break;
            case RootPath:
                break;
            case ExtensionFile:
                break;
            case ForwardOnOff:
                break;
            case SrcRteOnOff:
                break;
            case PolicyFilter:
                break;
            case MaxDGAssembly:
                break;
            case DefaultIPTTL:
                break;
            case MTUTimeout:
                break;
            case MTUPlateau:
                break;
            case MTUInterface:
                break;
            case MTUSubnet:
                break;
            case BroadcastAddress:
                break;
            case MaskDiscovery:
                break;
            case MaskSupplier:
                break;
            case RouterDiscovery:
                break;
            case RouterRequest:
                break;
            case StaticRouteTable: // TO BE IMPLEMENTED
                // Reply.createDHCPMessages(DHCPPacket.MessagesType.StaticRouteTable, InetAddress.getByName(DHCPImpl.getStaticRouteTable()));
                break;
            case Trailers:
                break;
            case ARPTimeout:
                break;
            case Ethernet:
                break;
            case DefaultTCPTTL:
                break;
            case KeepaliveTime:
                break;
            case KeepaliveData:
                break;
            case NISDomain:
                break;
            case NISServers:
                break;
            case NTPServers:
                break;
            case VendorSpecific:
                break;
            case NETBIOSNameSrv:
                break;
            case NETBIOSDistSrv:
                break;
            case NETBIOSNodeType:
                break;
            case NETBIOSScope:
                break;
            case XWindowFont:
                break;
            case XWindowManager:
                break;
            case IPAddressRequested:
                break;
            case AddressLeaseTime:

                Reply.createDHCPMessages(DHCPPacket.MessagesType.AddressLeaseTime, DHCPImpl.getAddressLeaseTime());

                break;
            case Overload:
                break;
            case DHCPMsgType:
                break;
            case DHCPServerId:

                Reply.createDHCPMessages(DHCPPacket.MessagesType.DHCPServerId, InetAddress.getByName(DHCPImpl.getDHCPServerIP()));

                break;
            case ParameterList:
                break;
            case DHCPErrorMessage:
                break;
            case DHCPMaxMsgSize:
                break;
            case RenewalTime:
                break;
            case RebindingTime:

                Reply.createDHCPMessages(DHCPPacket.MessagesType.RebindingTime, DHCPImpl.getRebindingTime());

                break;
            case VendorClassIdentifier:
                break;
            case ClientId:
                break;
            case NetWare_IPDomain:
                break;
            case NetWare_IPOption:
                break;
            case NISDomainName:
                break;
            case NISServerAddr:
                break;
            case TFTPServerName:
                break;
            case BootfileName:
                break;
            case HomeAgentAddrs:
                break;
            case SMTPServer:
                break;
            case POP3Server:
                break;
            case NNTPServer:
                break;
            case WWWServer:
                break;
            case FingerServer:
                break;
            case IRCServer:
                break;
            case StreetTalkServer:
                break;
            case STDAServer:
                break;
            case UserClass:
                break;
            case DirectoryAgent:
                break;
            case ServiceScope:
                break;
            case RapidCommit:
                break;
            case ClientFQDN:
                break;
            case RelayAgentInformation:
                break;
            case iSNS:
                break;
            case NDSServers:
                break;
            case NDSTreeName:
                break;
            case NDSContext:
                break;
            case BCMCSControllerDomainNamelist:
                break;
            case BCMCSControllerIPv4addressoption:
                break;
            case Authentication:
                break;
            case clientlasttransactiontimeoption:
                break;
            case ClientSystem:
                break;
            case ClientNDI:
                break;
            case LDAP:
                break;
            case UUIDGUID:
                break;
            case UserAuth:
                break;
            case GEOCONF_CIVIC:
                break;
            case PCode:
                break;
            case TCode:
                break;
            case NetinfoAddress:
                break;
            case NetinfoTag:
                break;
            case URL:
                break;
            case AutoConfig:
                break;
            case NameServiceSearch:
                break;
            case SubnetSelectionOption:
                break;
            case DomainSearch:
                break;
            case SIPServersDHCPOption:
                break;
            case ClasslessStaticRouteOption:
                break;
            case CCC:
                break;
            case GeoConfOption:
                break;
            case VIVendorClass:
                break;
            case VIVendorSpecificInformation:
                break;
            case dhcpstate:
                break;
            case datasource:
                break;
            case RebootTime:
                break;
            case OPTION_V4_ACCESS_DOMAIN:
                break;
            case SubnetAllocationOption:
                break;
            case VirtualSubnetSelectionOption:
                break;
            case TheEnd:
                break;
            default:
                throw new AssertionError(type.name());

        }
    }

    private void setRouter() {

    }

}
