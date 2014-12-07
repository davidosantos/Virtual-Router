/* 
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.PPP;

import DavidSantos.VirtualRouter.EthernetTypes;
import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;
import DavidSantos.VirtualRouter.MACAddress;
import DavidSantos.VirtualRouter.PPP.LCP.AuthenticationType;
import DavidSantos.VirtualRouter.PPP.LCP.LCPCodes;
import DavidSantos.VirtualRouter.PPP.LCP.LCPOptions;
import DavidSantos.VirtualRouter.PPP.LCP.LCPPacket;
import DavidSantos.VirtualRouter.PPP.LCP.MagicNumber;
import DavidSantos.VirtualRouter.PPP.PAP.PAPCodes;
import DavidSantos.VirtualRouter.PPP.PAP.PAPPacket;
import DavidSantos.VirtualRouter.RouterInterface;
import com.sun.org.apache.bcel.internal.Constants;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import javax.print.DocFlavor;

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
    MACAddress fromServer;
    MagicNumber Client_Magic_Number;
    MagicNumber Server_Magic_Number;
    List<LCPOptions> ServerAcknolegments;
    AuthenticationType AuthType;
    private byte LCP_questions_Identifier;
    private byte LCP_server_Questions_Identifier;
    List<LCPOptions> supportedOpitions = new ArrayList<>();
    
    
    //PAP
    private byte PAP_questions_Identifier;
    

    boolean isConnected = false;

    RouterInterface routerInterface;

    public PPPTransaction(RouterInterface routerInterface) {
        this.routerInterface = routerInterface;
        this.random.nextBytes(dataTagHostUniq);

        supportedOpitions.add(LCPOptions.Maximum_Receive_Unit);
        supportedOpitions.add(LCPOptions.Magic_Number);
        supportedOpitions.add(LCPOptions.Authentication_Protocol);
        supportedOpitions.add(LCPOptions.Multilink_EndPoint);

        AuthType = AuthenticationType.PAP;

        ServerAcknolegments = new ArrayList<>();

    }

    void Send(PPPoEDiscovery discovery) throws CustomExceptions {

    }

    private LCPOptions[] listToLCP(List<LCPOptions> options) {
        LCPOptions[] opt = new LCPOptions[options.size()];
        for (int i = 0; i < options.size(); i++) {
            opt[i] = options.get(i);
        }
        return opt;
    }

    public void onReceive_Session_St(PPPoESession session) throws CustomExceptions {
        switch (session.getProtocol()) {

            case LCP:
                switch (session.getLCPPayload().getCode()) {
                    case Configure_Rq:
                        //MUST transmit a Configure-Reject, or  Configure-Ack
                        List<LCPOptions> notSupported = new ArrayList<>();

                        this.LCP_server_Questions_Identifier = session.getLCPPayload().getIdentifier();

                        for (LCPOptions option : session.getLCPPayload().getPayload()) {
                            if (supportedOpitions.indexOf(option) == -1) { //if note exists in the supportedOpitions, then
                                notSupported.add(option);// add tp not notSupported
                            }
                        }
                        if (notSupported.size() > 0) { //if there is any not notSupported

                            LCPPacket packt = new LCPPacket(LCPCodes.Configure_Rej, LCP_server_Questions_Identifier, listToLCP(notSupported)); //collect the not supprted options

                            PPPoESession sessionReply = new PPPoESession(PPPProtocol_Ids.LCP, PPPCodes.Session_Data, SessionStabilished, packt); // join with the LCP protocou header

                            routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.fromServer, sessionReply.getBytes()); //send it to the server that we are talkin to

                        } else { //if all options are supported, then
                            //might send nak packet to correct values in the acceptable options
                            for (LCPOptions option : session.getLCPPayload().getPayload()) { //walk throgh the options
                                if (option == LCPOptions.Authentication_Protocol) { //find the Authentication_Protocol
                                    if (AuthenticationType.getTypeName((short) (option.getData()[0] << 8 | option.getData()[1]) & 0xFFFF) == AuthType) { // check if it matches with our supported authentication type

                                        LCPPacket lcppacket = new LCPPacket(LCPCodes.Configure_Ack, LCP_server_Questions_Identifier, session.getLCPPayload().getPayload()); //if it does match, then create a ack packet

                                        PPPoESession sessionReply = new PPPoESession(PPPProtocol_Ids.LCP, PPPCodes.Session_Data, SessionStabilished, lcppacket); // join with the LCP protocou header

                                        routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.fromServer, sessionReply.getBytes()); //tell the server we are ok

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

                                        routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.fromServer, sessionReply.getBytes()); // tell the server to correct the authentication type to match our this.AuthType.getType() 
                                    }
                                }

                                if (option == LCPOptions.Magic_Number) {
                                    this.Server_Magic_Number = new MagicNumber((int) (option.getData()[0] << 24 | option.getData()[1] << 16 | option.getData()[2] << 8 | option.getData()[3]) & 0xFFFFFFFF);
                                }

                            }
                        }

                        break;
                    case Configure_Ack:
                        // must macth up LCP_questions_Identifier
                        if (session.getLCPPayload().getIdentifier() == this.LCP_questions_Identifier) {
                            for (LCPOptions option : session.getLCPPayload().getPayload()) {
                                switch (option) {

                                    case Terminate_Reply:
                                        ServerAcknolegments.add(option);
                                        break;
                                    case Maximum_Receive_Unit:
                                        ServerAcknolegments.add(option);
                                        break;
                                    case Magic_Number:
                                        ServerAcknolegments.add(option);
                                        break;
                                }
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
                        if (this.fromServer != null) {
                            if (this.fromServer.equals(session.getFrom())) {
                                for (LCPOptions opt : session.getLCPPayload().getPayload()) {
                                    if (opt == LCPOptions.Terminate_Rq) {

                                        LCPOptions terminateReply = LCPOptions.Terminate_Reply;

                                        terminateReply.setData(opt.getData());
                                        terminateReply.setLength(opt.getLength());

                                        LCPPacket lcppacket = new LCPPacket(LCPCodes.Terminate_Ack, session.getLCPPayload().getIdentifier(), terminateReply); //if it does match, then create a ack packet

                                        PPPoESession sessionReply = new PPPoESession(PPPProtocol_Ids.LCP, PPPCodes.Session_Data, SessionStabilished, lcppacket); // join with the LCP protocou header

                                        routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.fromServer, sessionReply.getBytes()); //tell the server we are finished

                                        Client_Magic_Number = null;
                                        Server_Magic_Number = null;
                                        ServerAcknolegments = null;
                                        LCP_questions_Identifier = 0;
                                        LCP_server_Questions_Identifier = 0;
                                        break;
                                    }
                                }
                            }
                        }
                        break;
                    case Terminate_Ack:
                        if (this.fromServer.equals(session.getFrom())) {

                            fromServer = null;
                            Client_Magic_Number = null;
                            Server_Magic_Number = null;
                            ServerAcknolegments = null;
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
                        for (int optionIndex = 0; optionIndex < session.getLCPPayload().getPayload().length; optionIndex++) {

                            if (session.getLCPPayload().getPayload()[optionIndex] == LCPOptions.Echo_Rq) {
                                LCPOptions reply = LCPOptions.Echo_Reply;

                                reply.setData(session.getLCPPayload().getPayload()[optionIndex].getData());
                                reply.setLength(session.getLCPPayload().getPayload()[optionIndex].getLength());

                                for (int i = 0; i < this.Client_Magic_Number.toArray().length; i++) {
                                    reply.getData()[i] = this.Client_Magic_Number.toArray()[i];
                                }

                                LCPPacket lcppacket = new LCPPacket(LCPCodes.Echo_Reply, session.getLCPPayload().getIdentifier(), reply); //if it does match, then create a ack packet

                                PPPoESession sessionReply = new PPPoESession(PPPProtocol_Ids.LCP, PPPCodes.Session_Data, SessionStabilished, lcppacket); // join with the LCP protocou header

                                routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.fromServer, sessionReply.getBytes());
                                break;
                            }
                        }

                        break;
                    case Echo_Reply:
                        System.out.println(
                                "Echo Packet Reply");
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
                        this.isConnected = true;
                    } else {
                        throw new CustomExceptions("PAP: Connection failed, server message: " + session.getPAPPayload().getMessage());
                    }

                } else {
                    throw new CustomExceptions("PAP: Server replied with a different idenfifier, packet was discarded. server identifier: " + (session.getPAPPayload().getIdentifier() & 0xFF)
                            + " this client identifier: " + (this.PAP_questions_Identifier & 0xFF));
                }
                break;
        }

    }

    public void onReceive_Discovery_St(PPPoEDiscovery discovery) throws CustomExceptions {
        System.out.println("PPPoEDiscovery New packet;");

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
                    this.fromServer = discovery.getCode().getFrom();
                }

                for (TAGS tag : discovery.getPayload()) {
                    if (tag == TAGS.AC_Name) {
                        this.ACName = tag;
                    }
                }

                for (TAGS tag : discovery.getPayload()) {
                    if (tag == TAGS.AC_Cookie) {
                        this.ACCookie = tag;
                    }
                }

                short session = 0;

                TAGS service_name = TAGS.Service_Name;
                service_name.setData("David".getBytes());

                TAGS[] tags = new TAGS[3];
                tags[0] = service_name;
                tags[1] = hostUniq;
                tags[2] = ACCookie;

                PPPoEDiscovery discoveryRequest = new PPPoEDiscovery(PPPCodes.PADR, session, tags);

                routerInterface.sendWanData(EthernetTypes.PPP_Discovery_St, this.fromServer, discoveryRequest.getBytes());
                this.waitingFor = WaitingFor.Ack;

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
                    }
                }

                if (discovery.getCode().getFrom() == null) {
                    throw new CustomExceptions("Error the field 'From' of the packet received is null");
                } else {
                    this.fromServer = discovery.getCode().getFrom();
                }

                for (TAGS tag : discovery.getPayload()) {
                    if (tag == TAGS.AC_Cookie) {
                        if (Arrays.equals(this.ACCookie.getData(), tag.getData())) {
                            //Ok Cookie Match
                        } else {
                            throw new CustomExceptions("Invalid cookie received: " + Arrays.toString(tag.getData()) + " From " + discovery.getCode().getFrom().toString()
                                    + " The right is: " + Arrays.toString(this.ACCookie.getData()));
                        }
                    }
                }
                if (discovery.getSession_Id() == 0) {
                    throw new CustomExceptions("There was a error, session returned is 0: " + discovery.getCode().name() + " From " + discovery.getCode().getFrom().toString());
                } else {
                    this.SessionStabilished = discovery.getSession_Id();
                    System.out.println("Session is : " + this.SessionStabilished);
                    waitingFor = WaitingFor.Everything;

                    startLCP();

                }

            } else {
                throw new CustomExceptions("I was waitiong for a PADS Packet, But I received: " + discovery.getCode().name() + " From " + discovery.getCode().getFrom().toString());
            }
        } else if (waitingFor == WaitingFor.Everything) {
            if (discovery.getCode() == PPPCodes.PADT) {

                if (Arrays.equals(discovery.getCode().getFrom().getMac(), this.fromServer.getMac())) {
                    this.SessionStabilished = 0;
                    ACName = null;
                    ACCookie = null;
                    hostUniq = null;
                    fromServer = null;
                }

            }
        }
    }

    public void start() throws CustomExceptions {
        TAGS[] tags = new TAGS[2];
        TAGS hostunique = TAGS.Host_Uniq;
        hostunique.setData(dataTagHostUniq);

        TAGS service_name = TAGS.Service_Name;
        service_name.setData("David".getBytes());

        tags[0] = service_name;
        tags[1] = hostunique;

        short session = 0;

        PPPoEDiscovery discoveryReply = new PPPoEDiscovery(PPPCodes.PADI, session, tags);

        routerInterface.sendWanEthernetBroadcast(EthernetTypes.PPP_Discovery_St, discoveryReply.getBytes());
        this.waitingFor = WaitingFor.Offer;

    }

    private void startLCP() throws CustomExceptions {

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

        routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.fromServer, session.getBytes());

    }

    private void startPAP() throws CustomExceptions {
        this.PAP_questions_Identifier = (byte) random.nextInt();
        PAPPacket pap = new PAPPacket(PAPCodes.PasswordRequest, this.PAP_questions_Identifier, "Username", "Password");

        PPPoESession session = new PPPoESession(PPPProtocol_Ids.PAP, PPPCodes.Session_Data, SessionStabilished, pap);

        routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.fromServer, session.getBytes());
    }

    public void disconnect() throws CustomExceptions {

        if (isConnected) {
            LCPOptions[] opt = new LCPOptions[1];

            LCPOptions magicNumber = LCPOptions.Magic_Number;
            this.Client_Magic_Number = new MagicNumber(random.nextInt());
            magicNumber.setData(Client_Magic_Number.toArray());

            opt[0] = magicNumber;
            LCP_questions_Identifier = (byte) random.nextInt();
            LCPPacket packt = new LCPPacket(LCPCodes.Terminate_Rq, LCP_questions_Identifier, opt);

            PPPoESession session = new PPPoESession(PPPProtocol_Ids.LCP, PPPCodes.Session_Data, SessionStabilished, packt);

            routerInterface.sendWanData(EthernetTypes.PPP_Session_St, this.fromServer, session.getBytes());
            this.isConnected = false;
        } else {
            throw new CustomExceptions("Not connected yet");
        }
    }

    private enum WaitingFor {

        Offer,
        Ack,
        Everything,
        none;
    }

}
