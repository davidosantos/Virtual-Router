/* 
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.PPP;

import DavidSantos.VirtualRouter.EthernetTypes;
import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;
import DavidSantos.VirtualRouter.MACAddress;
import DavidSantos.VirtualRouter.NAT.NATTransaction;
import DavidSantos.VirtualRouter.PPP.CCP.CCPCodes;
import DavidSantos.VirtualRouter.PPP.CCP.CCPOptions;
import DavidSantos.VirtualRouter.PPP.CCP.CCPPacket;
import DavidSantos.VirtualRouter.PPP.IPCP.IPCPCodes;
import DavidSantos.VirtualRouter.PPP.IPCP.IPCPOptions;
import DavidSantos.VirtualRouter.PPP.IPCP.IPCPPacket;
import DavidSantos.VirtualRouter.PPP.LCP.AuthenticationType;
import DavidSantos.VirtualRouter.PPP.LCP.LCPCodes;
import DavidSantos.VirtualRouter.PPP.LCP.LCPOptions;
import DavidSantos.VirtualRouter.PPP.LCP.LCPPacket;
import DavidSantos.VirtualRouter.PPP.LCP.MagicNumber;
import DavidSantos.VirtualRouter.PPP.PAP.PAPCodes;
import DavidSantos.VirtualRouter.PPP.PAP.PAPPacket;
import DavidSantos.VirtualRouter.RouterInterface;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.wan.PPP;

/**
 *
 * @author root
 */
public class PPPTransaction {

    private WaitingFor waitingFor = WaitingFor.none;
    Random random = new Random();
    //PPP
    TAGS ACName;
    TAGS ACCookie;
    TAGS hostUniq;
    byte[] dataTagHostUniq = new byte[4]; //new byte[]{(byte) 0x94, (byte) 0x98, (byte) 0x00, (byte) 0x00,};
    short SessionStabilished; /// must test session before sending data.

    //LCP
    MACAddress connectedServer;
    MagicNumber Client_Magic_Number;
    MagicNumber Server_Magic_Number;
    List<LCPOptions> ServerAcknolegments = new ArrayList<>();
    AuthenticationType AuthType;
    private byte LCP_questions_Identifier;
    private byte LCP_server_Questions_Identifier;
    List<LCPOptions> LCP_supportedOpitions = new ArrayList<>();

    //PAP
    private byte PAP_questions_Identifier;

    //IPCP
    private byte IPCP_questions_Identifier;
    private byte IPCP_server_Questions_Identifier;
    List<IPCPOptions> IPCP_supportedOpitions = new ArrayList<>();
    private InetAddress gateway;
    private InetAddress ip;
    InetAddress primaryDNS;
    InetAddress secondaryDNS;

    //CCP
    private byte CCP_questions_Identifier;
    List<CCPOptions> CCP_supportedOpitions = new ArrayList<>();

    private boolean isConnected = false;

    RouterInterface routerInterface;

    public PPPTransaction(RouterInterface routerInterface) {
        this.routerInterface = routerInterface;
        this.random.nextBytes(dataTagHostUniq);

        LCP_supportedOpitions.add(LCPOptions.Maximum_Receive_Unit);
        LCP_supportedOpitions.add(LCPOptions.Magic_Number);
        LCP_supportedOpitions.add(LCPOptions.Authentication_Protocol);
        // LCP_supportedOpitions.add(LCPOptions.Multilink_EndPoint);

        AuthType = AuthenticationType.PAP;

        IPCP_supportedOpitions.add(IPCPOptions.IPAddress);
        IPCP_supportedOpitions.add(IPCPOptions.PrimaryDNSServerAddress);
        IPCP_supportedOpitions.add(IPCPOptions.SecondaryDNSServerAddress);

    }

    private LCPOptions[] listToLCP(List<LCPOptions> options) {
        LCPOptions[] opt = new LCPOptions[options.size()];
        for (int i = 0; i < options.size(); i++) {
            opt[i] = options.get(i);
        }
        return opt;
    }

    private IPCPOptions[] listToIPCP(List<IPCPOptions> options) {
        IPCPOptions[] opt = new IPCPOptions[options.size()];
        for (int i = 0; i < options.size(); i++) {
            opt[i] = options.get(i);
        }
        return opt;
    }

    private CCPOptions[] listToCCP(List<CCPOptions> options) {
        CCPOptions[] opt = new CCPOptions[options.size()];
        for (int i = 0; i < options.size(); i++) {
            opt[i] = options.get(i);
        }
        return opt;
    }

    public void onReceive_Session_St(PPPoESession session) throws CustomExceptions, UnknownHostException {

        if (SessionStabilished != 0) {

            switch (session.getProtocol()) {

                case LCP:
                    switch (session.getLCPPayload().getCode()) {

                        case Configure_Rq:

                            //MUST transmit a Configure-Reject, or  Configure-Ack
                            List<LCPOptions> LCPnotSupported = new ArrayList<>();

                            this.LCP_server_Questions_Identifier = session.getLCPPayload().getIdentifier();

                            for (LCPOptions option : session.getLCPPayload().getPayload()) {
                                if (LCP_supportedOpitions.indexOf(option) == -1) { //if note exists in the supportedOpitions, then
                                    LCPnotSupported.add(option);// add tp not notSupported
                                }
                            }
                            if (LCPnotSupported.size() > 0) { //if there is any not notSupported

                                LCPPacket packt = new LCPPacket(LCPCodes.Configure_Rej, LCP_server_Questions_Identifier, listToLCP(LCPnotSupported)); //collect the not supprted options

                                PPPoESession LCPsessionReply = new PPPoESession(PPPProtocol_Ids.LCP, PPPCodes.Session_Data, SessionStabilished, packt); // join with the Session protocou header

                                routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.connectedServer, LCPsessionReply.getBytes()); //send it to the server that we are talkin to

                            } else { //if all options are supported, then
                                //might send nak packet to correct values in the acceptable options
                                for (LCPOptions option : session.getLCPPayload().getPayload()) { //walk throgh the options
                                    if (option == LCPOptions.Authentication_Protocol) { //find the Authentication_Protocol
                                        if (AuthenticationType.getTypeName((short) (option.getData()[0] << 8 | option.getData()[1]) & 0xFFFF) == AuthType) { // check if it matches with our supported authentication type

                                            LCPPacket lcppacket = new LCPPacket(LCPCodes.Configure_Ack, LCP_server_Questions_Identifier, session.getLCPPayload().getPayload()); //if it does match, then create a ack packet

                                            PPPoESession sessionReply = new PPPoESession(PPPProtocol_Ids.LCP, PPPCodes.Session_Data, SessionStabilished, lcppacket); // join with the Session protocol header

                                            routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.connectedServer, sessionReply.getBytes()); //tell the server we are ok

                                            routerInterface.info("PPPoE LCP started");

                                            // we are ready to start authentication process here, if authentication type is chap, then we should just wait for chap packet, the server will surely send
                                            // when authetication is successful set isConnected to true
                                            switch (AuthType) {
                                                case CHAP:
                                                    break;
                                                case EAP:
                                                    break;
                                                case SPAP:
                                                    break;
                                                case PAP:
                                                    startPAP();
                                                    break;
                                                default:
                                                    throw new AssertionError(AuthType.name());

                                            }

                                        } else { // if the authentication type doesn't match, then:

                                            option.setData(new byte[]{(byte) (this.AuthType.getType() >> 8), (byte) this.AuthType.getType()}); //set the option data field with the supported authentication type
                                            option.setLength((byte) 4); // Length must include the length and type fields, and must be set, otherwise a error will occur 
                                            LCPPacket lcppacket = new LCPPacket(LCPCodes.Configure_Nak, LCP_server_Questions_Identifier, session.getLCPPayload().getPayload()); //create a corrected 

                                            PPPoESession sessionReply = new PPPoESession(PPPProtocol_Ids.LCP, PPPCodes.Session_Data, SessionStabilished, lcppacket); // join with the LCP protocou header

                                            routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.connectedServer, sessionReply.getBytes()); // tell the server to correct the authentication type to match our this.AuthType.getType() 
                                        }
                                    }

                                    if (option == LCPOptions.Magic_Number) {
                                        //bytes[0] << 24 | (bytes[1] & 0xFF) << 16 | (bytes[2] & 0xFF) << 8 | (bytes[3] & 0xFF)
                                        this.Server_Magic_Number = new MagicNumber(option.getData()[0] << 24 | (option.getData()[1] & 0xff) << 16 | (option.getData()[2] & 0xFF) << 8 | (option.getData()[3] & 0xFF));
                                        routerInterface.info("PPPoE LCP server magic number: 0x" + Integer.toHexString(this.Server_Magic_Number.getNumer()));
                                    }

                                }
                            }

                            break;
                        case Configure_Ack:
                            // must match up LCP_questions_Identifier
                            if (session.getLCPPayload().getIdentifier() == this.LCP_questions_Identifier) {
                                for (LCPOptions option : session.getLCPPayload().getPayload()) {

                                    ServerAcknolegments.add(option);

                                }

                            } else {
                                throw new CustomExceptions("LCP: Server replied with a different idenfifier, packet was discarded. server identifier: " + (session.getLCPPayload().getIdentifier() & 0xFF)
                                        + " this client identifier: " + (this.LCP_questions_Identifier & 0xFF));
                            }

                            break;
                        case Configure_Nak:

                            break;
                        case Configure_Rej:

                            break;
                        case Terminate_Rq:
                            if (this.connectedServer != null) {
                                if (this.connectedServer.equals(session.getFrom())) {
                                    for (LCPOptions opt : session.getLCPPayload().getPayload()) {
                                        if (opt == LCPOptions.Terminate_Rq) {

                                            LCPOptions terminateReply = LCPOptions.Terminate_Reply;

                                            terminateReply.setData(opt.getData());
                                            terminateReply.setLength(opt.getLength());

                                            LCPPacket lcppacket = new LCPPacket(LCPCodes.Terminate_Ack, session.getLCPPayload().getIdentifier(), terminateReply); //if it does match, then create a ack packet

                                            PPPoESession sessionReply = new PPPoESession(PPPProtocol_Ids.LCP, PPPCodes.Session_Data, SessionStabilished, lcppacket); // join with the LCP protocou header

                                            routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.connectedServer, sessionReply.getBytes()); //tell the server we are finished
                                            routerInterface.info("Terminate Request from " + session.getFrom().toString());
                                            Client_Magic_Number = null;
                                            Server_Magic_Number = null;
                                            ServerAcknolegments.clear();
                                            LCP_questions_Identifier = 0;
                                            LCP_server_Questions_Identifier = 0;
                                            isConnected = false;
                                            break;
                                        }
                                    }
                                }
                            }
                            break;
                        case Terminate_Ack:
                            if (this.connectedServer.equals(session.getFrom())) {
                                routerInterface.info("PPPoE LCP Terminate ack from " + session.getFrom().toString());
                                Client_Magic_Number = null;
                                Server_Magic_Number = null;
                                ServerAcknolegments.clear();
                                LCP_questions_Identifier = 0;
                                LCP_server_Questions_Identifier = 0;
                                this.isConnected = false;

                            }
                            break;
                        case Code_Rej:

                            break;
                        case Protocol_Rej:

                            break;
                        case Echo_Rq:
                            if (this.isConnected) {
                                for (int optionIndex = 0; optionIndex < session.getLCPPayload().getPayload().length; optionIndex++) {

                                    if (session.getLCPPayload().getPayload()[optionIndex] == LCPOptions.Echo_Rq) {
                                        routerInterface.info("Echo Request from " + session.getFrom().toString());
                                        LCPOptions reply = LCPOptions.Echo_Reply;

                                        reply.setData(session.getLCPPayload().getPayload()[optionIndex].getData());
                                        reply.setLength(session.getLCPPayload().getPayload()[optionIndex].getLength());

                                        for (int i = 0; i < this.Client_Magic_Number.toArray().length; i++) {
                                            reply.getData()[i] = this.Client_Magic_Number.toArray()[i];
                                        }

                                        LCPPacket lcppacket = new LCPPacket(LCPCodes.Echo_Reply, session.getLCPPayload().getIdentifier(), reply); //if it does match, then create a ack packet

                                        PPPoESession sessionReply = new PPPoESession(PPPProtocol_Ids.LCP, PPPCodes.Session_Data, SessionStabilished, lcppacket); // join with the LCP protocou header

                                        routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.connectedServer, sessionReply.getBytes());
                                        routerInterface.info("Echo Reply was sent.");
                                        break;
                                    }
                                }
                            }

                            break;
                        case Echo_Reply:

                            break;
                        case Discard_Rq:

                            break;
                        case LinkQuality_Rpt:

                            break;

                    }
                    break;
                case PAP:
                    if (session.getPAPPayload().getIdentifier() == this.PAP_questions_Identifier) {
                        if (session.getPAPPayload().getCode() == PAPCodes.PasswordAck) {

                            startIPCP();
                        } else {
                            throw new CustomExceptions("PAP: Connection failed, server message: " + session.getPAPPayload().getMessage());
                        }

                    } else {
                        throw new CustomExceptions("PAP: Server replied with a different idenfifier, packet was discarded. server identifier: " + (session.getPAPPayload().getIdentifier() & 0xFF)
                                + " this client identifier: " + (this.PAP_questions_Identifier & 0xFF));
                    }
                    break;

                case IPCP:

                    switch (session.getIPCPPayload().getCode()) {
                        case RESERVED:
                            break;
                        case Configure_Rq:

                            //MUST transmit a Configure-Reject, or  Configure-Ack
                            List<IPCPOptions> IPCPnotSupported = new ArrayList<>();

                            this.IPCP_server_Questions_Identifier = session.getIPCPPayload().getIdentifier();

                            for (IPCPOptions option : session.getIPCPPayload().getPayload()) {
                                if (IPCP_supportedOpitions.indexOf(option) == -1) { //if not exists in the supportedOpitions, then
                                    IPCPnotSupported.add(option);// add to not notSupported
                                }
                            }
                            if (IPCPnotSupported.size() > 0) { //if there is any not notSupported

                                IPCPPacket packt = new IPCPPacket(IPCPCodes.Configure_Rej, IPCP_server_Questions_Identifier, listToIPCP(IPCPnotSupported)); //collect the not supported options

                                PPPoESession IPCPsessionReply = new PPPoESession(PPPProtocol_Ids.IPCP, PPPCodes.Session_Data, SessionStabilished, packt); // join with the Session protocou header

                                routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.connectedServer, IPCPsessionReply.getBytes()); //send it to the server that we are talking to

                            } else { //if all options are supported, then

                                for (IPCPOptions option : session.getIPCPPayload().getPayload()) { //walk throgh the options

                                    if (option == IPCPOptions.IPAddress) { // this is the gateway, because gateways comes in request packet

                                        this.gateway = option.getIP();
                                        routerInterface.info("Gateway obtido: " + this.gateway.toString());
                                        IPCPPacket IPCPReply = new IPCPPacket(IPCPCodes.Configure_Ack, IPCP_server_Questions_Identifier, session.getIPCPPayload().getPayload());

                                        PPPoESession IPCPSession = new PPPoESession(PPPProtocol_Ids.IPCP, PPPCodes.Session_Data, SessionStabilished, IPCPReply);

                                        routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.connectedServer, IPCPSession.getBytes()); //send it to the server that we are talking to

                                        //now, lets get our Ip address
                                        break;
                                    }
                                }
                            }

                            break;
                        case Configure_Ack:
                            if (this.IPCP_questions_Identifier == session.getIPCPPayload().getIdentifier()) {
                                for (IPCPOptions option : session.getIPCPPayload().getPayload()) {
                                    switch (option) {
                                        case IPAddresses:
                                            break;
                                        case IPCompressionProtocol:
                                            break;
                                        case IPAddress:

                                            this.ip = option.getIP();
                                            routerInterface.info("IP obtido: " + this.ip.toString());
                                            this.isConnected = true;
                                            break;
                                        case MobileIPv4:
                                            break;
                                        case PrimaryDNSServerAddress:
                                            this.primaryDNS = option.getIP();
                                            routerInterface.info("Primary DNS obtido: " + this.primaryDNS.toString());
                                            break;
                                        case PrimaryNBNSServerAddress:
                                            break;
                                        case SecondaryDNSServerAddress:
                                            this.secondaryDNS = option.getIP();
                                            routerInterface.info("Secondary DNS obtido: " + this.secondaryDNS.toString());
                                            break;
                                        case SecondaryNBNSServerAddress:
                                            break;
                                        default:
                                            throw new AssertionError(option.name());

                                    }
                                }

                            } else {
                                throw new CustomExceptions("IPCP ack: Server replied with a different idenfifier, packet was discarded. server identifier: " + (session.getIPCPPayload().getIdentifier() & 0xFF)
                                        + " this client identifier: " + (this.IPCP_questions_Identifier & 0xFF));
                            }
                            break;
                        case Configure_Nak:
                            if (this.IPCP_questions_Identifier == session.getIPCPPayload().getIdentifier()) {

                                session.getIPCPPayload().setCode(IPCPCodes.Configure_Rq);

                                PPPoESession confirmation = new PPPoESession(PPPProtocol_Ids.IPCP, PPPCodes.Session_Data, SessionStabilished, session.getIPCPPayload());

                                routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.connectedServer, confirmation.getBytes()); //send it to the server that we are talking to

                            } else {
                                throw new CustomExceptions("IPCP nak: Server replied with a different idenfifier, packet was discarded. server identifier: " + (session.getIPCPPayload().getIdentifier() & 0xFF)
                                        + " this client identifier: " + (this.IPCP_questions_Identifier & 0xFF));
                            }
                            break;
                        case Configure_Rej:

                            break;
                        case Terminate_Rq:

                            break;
                        case Terminate_Ack:

                            if (this.IPCP_questions_Identifier == session.getIPCPPayload().getIdentifier()) {

                            }
                            break;

                        case Code_Rej:
                            break;
                        default:
                            throw new AssertionError(session.getIPCPPayload().getCode().name());

                    }

                    break;
                case CCP:

                    switch (session.getCCPPayload().getCode()) {
                        case RESERVED:
                            break;
                        case Configure_Rq:

                            //MUST transmit a Configure-Reject, or  Configure-Ack
                            startCCP();
                            List<CCPOptions> CCPnotSupported = new ArrayList<>();

                            this.CCP_questions_Identifier = session.getCCPPayload().getIdentifier();

                            for (CCPOptions option : session.getCCPPayload().getPayload()) {
                                if (CCP_supportedOpitions.indexOf(option) == -1) { //if not exists in the supportedOpitions, then
                                    CCPnotSupported.add(option);// add to not notSupported
                                }
                            }
                            if (CCPnotSupported.size() > 0) { //if there is any not notSupported

                                CCPPacket packet = new CCPPacket(CCPCodes.Configure_Rej, CCP_questions_Identifier, listToCCP(CCPnotSupported)); //collect the not supported options

                                PPPoESession CCPsessionReply = new PPPoESession(PPPProtocol_Ids.CCP, PPPCodes.Session_Data, SessionStabilished, packet); // join with the Session protocou header

                                routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.connectedServer, CCPsessionReply.getBytes()); //send it to the server that we are talking to

                            } else { //if all options are supported, then

                                for (CCPOptions option : session.getCCPPayload().getPayload()) { //walk throgh the options

                                }
                            }

                            break;
                        case Configure_Ack:
                            break;
                        case Configure_Nak:
                            break;
                        case Configure_Rej:
                            break;
                        case Terminate_Rq:

                            if (this.connectedServer != null) {
                                if (this.connectedServer.equals(session.getFrom())) {
                                    for (CCPOptions opt : session.getCCPPayload().getPayload()) {

                                        CCPOptions terminateReply = CCPOptions.Terminate_Rq;

                                        terminateReply.setData(opt.getData());
                                        terminateReply.setLength(opt.getLength());

                                        CCPPacket ccppacket = new CCPPacket(CCPCodes.Terminate_Ack, session.getCCPPayload().getIdentifier(), terminateReply); //if it does match, then create a ack packet

                                        PPPoESession sessionReply = new PPPoESession(PPPProtocol_Ids.CCP, PPPCodes.Session_Data, SessionStabilished, ccppacket); // join with the LCP protocou header

                                        routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.connectedServer, sessionReply.getBytes()); //tell the server we are finished

                                        break;

                                    }
                                }
                            }

                            break;
                        case Terminate_Ack:
                            break;
                        case Code_Rej:
                            break;
                        default:
                            throw new AssertionError(session.getCCPPayload().getCode().name());

                    }

                    break;

                case IPv4:
                    
                    NATTransaction.newIncoming(session.getPcapPayload());
                    break;
            }
        } else {
            throw new CustomExceptions("PPPoE Error: Received session packet when there was no stabilished session.");
        }

    }

    public void onReceive_Discovery_St(PPPoEDiscovery discovery) throws CustomExceptions {
        if (waitingFor == WaitingFor.Offer) {
            if (discovery.getCode() == PPPCodes.PADO) {

                for (TAGS tag : discovery.getPayload()) {
                    if (tag == TAGS.Host_Uniq) {
                        if (Arrays.equals(tag.getData(), dataTagHostUniq)) {
                            this.hostUniq = tag;
                        } else {
                            throw new CustomExceptions("Error when treating PADO the field HostUniq of the packet received is differs from the sent, sent was: "
                                    + Arrays.toString(dataTagHostUniq) + " received is: " + Arrays.toString(tag.getData()));
                        }
                    }
                }

                if (discovery.getCode().getFrom() == null) {
                    throw new CustomExceptions("Error the field 'From' of the packet received is null");
                } else {
                    this.connectedServer = discovery.getCode().getFrom();
                }

                for (TAGS tag : discovery.getPayload()) {

                    switch (tag) {
                        case AC_Name:
                            this.ACName = tag;
                            break;
                        case AC_Cookie:
                            this.ACCookie = tag;
                    }
                }

                short session = 0;

                TAGS service_name = TAGS.Service_Name;
                service_name.setData(routerInterface.getPPPoEServiceName().getBytes());

                TAGS[] tags = new TAGS[3];
                tags[0] = service_name;
                tags[1] = hostUniq;
                tags[2] = ACCookie;

                PPPoEDiscovery discoveryRequest = new PPPoEDiscovery(PPPCodes.PADR, session, tags);

                routerInterface.sendWanData(EthernetTypes.PPP_Discovery_St, this.connectedServer, discoveryRequest.getBytes());
                this.waitingFor = WaitingFor.Ack;
                
                routerInterface.info("Waiting for ack");

            } else {
                throw new CustomExceptions("I was waitiong for a PADO Packet, But I received: " + discovery.getCode().name() + " From " + discovery.getCode().getFrom().toString());
            }
        } else if (waitingFor == WaitingFor.Ack) {
            if (discovery.getCode() == PPPCodes.PADS) {

                for (TAGS tag : discovery.getPayload()) {
                    if (tag == TAGS.Host_Uniq) {
                        if (Arrays.equals(tag.getData(), dataTagHostUniq)) {
                            this.hostUniq = tag;
                        } else {
                            throw new CustomExceptions("Error when treating PADS the field HostUniq of the packet received is differs from the sent, sent was: "
                                    + Arrays.toString(dataTagHostUniq) + " received is: " + Arrays.toString(tag.getData()));
                        }
                        break;
                    }
                }

                if (discovery.getCode().getFrom() == null) {
                    throw new CustomExceptions("Error the field 'From' of the packet received is null");
                } else {
                    this.connectedServer = discovery.getCode().getFrom();
                }

                for (TAGS tag : discovery.getPayload()) {
                    if (tag == TAGS.AC_Cookie) {
                        if (!Arrays.equals(this.ACCookie.getData(), tag.getData())) {

                            throw new CustomExceptions("Invalid cookie received: " + Arrays.toString(tag.getData()) + " From " + discovery.getCode().getFrom().toString()
                                    + " The right is: " + Arrays.toString(this.ACCookie.getData()));
                        }
                    }
                }
                if (discovery.getSession_Id() == 0) {
                    throw new CustomExceptions("There was a error, session returned is 0: " + discovery.getCode().name() + " From " + discovery.getCode().getFrom().toString());
                } else {
                    this.SessionStabilished = discovery.getSession_Id();
                    routerInterface.info("Stabilished Session: 0x" + Integer.toHexString(SessionStabilished));
                    waitingFor = WaitingFor.Everything;
                    routerInterface.info("Waiting for all packets.");
                    startLCP();

                }

            } else {
                throw new CustomExceptions("I was waitiong for a PADS Packet, But I received: " + discovery.getCode().name() + " From " + discovery.getCode().getFrom().toString());
            }
        } else if (waitingFor == WaitingFor.Everything) {
            if (discovery.getCode() == PPPCodes.PADT) {
                if (SessionStabilished > 0) {
                    if (Arrays.equals(discovery.getCode().getFrom().getMac(), this.connectedServer.getMac())) {
                        routerInterface.info("PPPoE Terminate session 0x" + Integer.toHexString(SessionStabilished));
                        this.SessionStabilished = 0;
                        ACName = null;
                        ACCookie = null;
                        hostUniq = null;
                        connectedServer = null;
                        isConnected = false;
                    }
                }

            }
        }
    }

    public void start() throws CustomExceptions {

        if (!this.isConnected) {
            routerInterface.info("PPPoE is starting");
            TAGS[] tags = new TAGS[2];
            TAGS hostunique = TAGS.Host_Uniq;
            hostunique.setData(dataTagHostUniq);

            TAGS service_name = TAGS.Service_Name;
            service_name.setData(routerInterface.getPPPoEServiceName().getBytes());

            tags[0] = service_name;
            tags[1] = hostunique;

            short session = 0;

            PPPoEDiscovery discoveryReply = new PPPoEDiscovery(PPPCodes.PADI, session, tags);

            routerInterface.sendWanEthernetBroadcast(EthernetTypes.PPP_Discovery_St, discoveryReply.getBytes());
            this.waitingFor = WaitingFor.Offer;
            routerInterface.info("Waiting for an offer...");
        } else {
            throw new CustomExceptions("Router is already connected");
        }

    }

    private void startLCP() throws CustomExceptions {
        routerInterface.info("PPPoE LCP is starting");
        LCPOptions[] opt = new LCPOptions[2];

        LCPOptions maxUnit = LCPOptions.Maximum_Receive_Unit;
        maxUnit.setData(new byte[]{(byte) 0x05, (byte) 0xd4});

        LCPOptions magicNumber = LCPOptions.Magic_Number;
        this.Client_Magic_Number = new MagicNumber(random.nextInt());
        magicNumber.setData(Client_Magic_Number.toArray());

        opt[0] = maxUnit;
        opt[1] = magicNumber;
        LCP_questions_Identifier = (byte) random.nextInt();
        LCPPacket packt = new LCPPacket(LCPCodes.Configure_Rq, LCP_questions_Identifier, opt);

        PPPoESession session = new PPPoESession(PPPProtocol_Ids.LCP, PPPCodes.Session_Data, SessionStabilished, packt);

        routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.connectedServer, session.getBytes());

    }

    private void startPAP() throws CustomExceptions {
        routerInterface.info("PPPoE PAP is starting");
        this.PAP_questions_Identifier = (byte) random.nextInt();
        PAPPacket pap = new PAPPacket(PAPCodes.PasswordRequest, this.PAP_questions_Identifier, routerInterface.getPPPoEUser()[0], routerInterface.getPPPoEUser()[1]);

        PPPoESession session = new PPPoESession(PPPProtocol_Ids.PAP, PPPCodes.Session_Data, SessionStabilished, pap);

        routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.connectedServer, session.getBytes());
    }

    private void startIPCP() throws CustomExceptions, UnknownHostException {
        routerInterface.info("PPPoE IPCP is starting");
        IPCPOptions[] opt = new IPCPOptions[3];

        IPCPOptions ip = IPCPOptions.IPAddress;
        ip.setIP(InetAddress.getByName("0.0.0.0"));
        ip.setLength((byte) 6);

        IPCPOptions priDNS = IPCPOptions.PrimaryDNSServerAddress;
        priDNS.setIP(InetAddress.getByName("0.0.0.0"));
        priDNS.setLength((byte) 6);

        IPCPOptions secDNS = IPCPOptions.SecondaryDNSServerAddress;
        secDNS.setIP(InetAddress.getByName("0.0.0.0"));
        secDNS.setLength((byte) 6);

        this.Client_Magic_Number = new MagicNumber(random.nextInt());

        opt[0] = ip;
        opt[1] = priDNS;
        opt[2] = secDNS;

        IPCP_questions_Identifier = (byte) random.nextInt();

        IPCPPacket packt = new IPCPPacket(IPCPCodes.Configure_Rq, IPCP_questions_Identifier, opt);

        PPPoESession session = new PPPoESession(PPPProtocol_Ids.IPCP, PPPCodes.Session_Data, SessionStabilished, packt);

        routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.connectedServer, session.getBytes());

    }

    private void startCCP() throws CustomExceptions {
        routerInterface.info("PPPoE CCP is starting");
        this.CCP_questions_Identifier = (byte) random.nextInt();
        CCPOptions[] opt = new CCPOptions[0];

        CCPPacket ccp = new CCPPacket(CCPCodes.Configure_Rq, this.CCP_questions_Identifier, opt);

        PPPoESession session = new PPPoESession(PPPProtocol_Ids.CCP, PPPCodes.Session_Data, SessionStabilished, ccp);

        routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.connectedServer, session.getBytes());
    }

    public void sendEncapsulatedData(byte[] data) throws CustomExceptions {

        PPPoESession session = new PPPoESession(PPPProtocol_Ids.IPv4, PPPCodes.Session_Data, SessionStabilished, data); //encapsulate

        routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.connectedServer, session.getBytes()); //send
    }

    public void disconnect() throws CustomExceptions {

        if (isConnected) {

            routerInterface.info("Disconnecting");
            LCPOptions[] opt = new LCPOptions[1];

            LCPOptions magicNumber = LCPOptions.Magic_Number;
            this.Client_Magic_Number = new MagicNumber(random.nextInt());
            magicNumber.setData(Client_Magic_Number.toArray());

            opt[0] = magicNumber;
            LCP_questions_Identifier = (byte) random.nextInt();

            LCPPacket packt = new LCPPacket(LCPCodes.Terminate_Rq, LCP_questions_Identifier, opt);

            PPPoESession session = new PPPoESession(PPPProtocol_Ids.LCP, PPPCodes.Session_Data, SessionStabilished, packt);

            routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.connectedServer, session.getBytes());

            this.isConnected = false;

        } else {
            throw new CustomExceptions("PPPoE is not connected yet");
        }
    }

    public boolean isConnected() {
        return isConnected;
    }

    public InetAddress getGateway() {
        return gateway;
    }

    public InetAddress getIp() {
        return ip;
    }

    private enum WaitingFor {

        Offer,
        Ack,
        Everything,
        none;
    }

}
