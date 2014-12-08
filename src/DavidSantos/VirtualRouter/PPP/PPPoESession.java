/*
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.PPP;

import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;
import DavidSantos.VirtualRouter.MACAddress;
import DavidSantos.VirtualRouter.PPP.CCP.CCPCodes;
import DavidSantos.VirtualRouter.PPP.CCP.CCPOptions;
import DavidSantos.VirtualRouter.PPP.CCP.CCPPacket;
import DavidSantos.VirtualRouter.PPP.IPCP.IPCPCodes;
import DavidSantos.VirtualRouter.PPP.IPCP.IPCPOptions;
import DavidSantos.VirtualRouter.PPP.IPCP.IPCPPacket;
import DavidSantos.VirtualRouter.PPP.LCP.LCPCodes;
import DavidSantos.VirtualRouter.PPP.LCP.LCPOptions;
import DavidSantos.VirtualRouter.PPP.LCP.LCPPacket;
import DavidSantos.VirtualRouter.PPP.PAP.PAPCodes;
import DavidSantos.VirtualRouter.PPP.PAP.PAPPacket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author root
 */
public class PPPoESession {

    private final byte typeAndVersion = 0x11;//the only version and type supported
    private PPPCodes code;
    private short session_Id;
    private short length;
    private PPPProtocol_Ids protocol;
    private MACAddress From;
    private LCPPacket LCPPayload;
    private PAPPacket PAPPayload;
    private IPCPPacket IPCPPayload;
    private CCPPacket CCPPayload;

    public PPPoESession(PPPCodes code, short session_Id, short length, byte[] payload, MACAddress from) throws CustomExceptions, UnknownHostException {

        this.code = code;
        this.session_Id = session_Id;
        this.length = length;
        int counter = 0;
        this.protocol = PPPProtocol_Ids.getTypeName((short) ((short) (payload[counter++] << 8 | payload[counter++] & 0xFF) & 0xFFFF));

        switch (protocol) {
            case LCP:
                LCPCodes LCPCode = LCPCodes.getCode(payload[counter++] & 0xFF);
                byte LCPIdentifier = payload[counter++];
                short LCPLength = (short) (payload[counter++] << 8 | payload[counter++] & 0xFF);

                List<LCPOptions> LCPOpt = new ArrayList<>();
                if (!(LCPCode == LCPCodes.Terminate_Rq
                        || LCPCode == LCPCodes.Terminate_Ack
                        || LCPCode == LCPCodes.Echo_Rq
                        || LCPCode == LCPCodes.Echo_Reply)) {
                    for (int i = counter; i < payload.length;) {
                        //    0                   1                   2                   3
                        //    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                        //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                        //   |     Type      |    Length     |      Maximum-Receive-Unit     |
                        //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                        //
                        //
                        //   Type 1 byte  Length  1 byte

                        LCPOptions option = LCPOptions.getTypeName(payload[i++] & 0xFF);
                        option.setLength((byte) (payload[i++]));
                        //-2 for Type end Length
                        option.setData(new byte[option.getLength() - 2]);
                        for (int j = 0; j < option.getLength() - 2; j++) {
                            option.getData()[j] = (byte) (payload[i++] & 0xFF);
                        }

                        LCPOpt.add(option);
                    }
                } else { //these has no options fields
                    LCPOptions option;
                    switch (LCPCode) {
                        case Terminate_Rq:
                            option = LCPOptions.Terminate_Rq;
                            break;
                        case Terminate_Ack:
                            option = LCPOptions.Terminate_Reply;
                            break;
                        case Echo_Rq:
                            option = LCPOptions.Echo_Rq;
                            break;
                        case Echo_Reply:
                            option = LCPOptions.Echo_Reply;
                            break;
                        default:
                            option = null;
                    }
                    if (option != null) {
                        option.setData(new byte[LCPLength - 4]);
                        option.setLength((byte) LCPLength);
                        for (int j = 0; j < option.getLength() - 4; j++) {
                            option.getData()[j] = (byte) (payload[counter++] & 0xFF);
                        }

                        LCPOpt.add(option);
                    }

                }

                LCPOptions[] LCPvalues = new LCPOptions[LCPOpt.size()];

                for (int i = 0; i < LCPOpt.size(); i++) {
                    LCPvalues[i] = LCPOpt.get(i);
                }

                LCPPayload = new LCPPacket(LCPCode, LCPIdentifier, LCPLength, LCPvalues);

                break;

            case PAP:
                PAPCodes PAPCode = PAPCodes.getCodeName((byte) (payload[counter++] & 0xFF));
                byte PAPIdentifier = payload[counter++];
                short PAPLength = (short) (payload[counter++] << 8 | payload[counter++] & 0xFF);
                byte messageLength = (byte) (payload[counter++] & 0xFF);

                byte[] message = new byte[messageLength];

                for (int i = 0; i < messageLength; i++) {
                    message[i] = (byte) (payload[counter++] & 0xFF);
                }

                this.PAPPayload = new PAPPacket(PAPCode, PAPIdentifier, PAPLength, message);

                break;

            case IPCP:
                IPCPCodes IPCPCode = IPCPCodes.getCode((byte) (payload[counter++] & 0xFF));
                byte IPCPIdentifier = payload[counter++];
                short IPCPLength = (short) (payload[counter++] << 8 | payload[counter++] & 0xFF);

                List<IPCPOptions> ipcpOptions = new ArrayList<>();

                for (; counter < IPCPLength;) {
                    IPCPOptions IPCPoption = IPCPOptions.getOptionName((byte) (payload[counter++] & 0xFF));
                    byte IPCPOptionLength = (byte) (payload[counter++] & 0xFF);
                    IPCPoption.setLength(IPCPOptionLength);
                    byte[] ip = new byte[IPCPOptionLength - 2];

                    for (int i = 0; i < ip.length; i++) {
                        ip[i] = (byte) (payload[counter++] & 0xFF);
                    }

                    IPCPoption.setIP(InetAddress.getByAddress(ip)); //might throw host unknown exception due to Ip compression option is not an ip

                    ipcpOptions.add(IPCPoption);
                }

                IPCPOptions[] options = new IPCPOptions[ipcpOptions.size()];

                for (int i = 0; i < ipcpOptions.size(); i++) {
                    options[i] = ipcpOptions.get(i);
                }

                this.IPCPPayload = new IPCPPacket(IPCPCode, IPCPIdentifier, IPCPLength, options);
                break;
            case CCP:
                CCPCodes CCPCode = CCPCodes.getCode((byte) (payload[counter++] & 0xFF));
                byte CCPIdentifier = payload[counter++];
                short CCPLength = (short) (payload[counter++] << 8 | payload[counter++] & 0xFF);

                List<CCPOptions> ccpOptions = new ArrayList<>();

                for (; counter < CCPLength;) {
                    CCPOptions CCPoption = CCPOptions.getOptionName((byte) (payload[counter++] & 0xFF));
                    byte CCPOptionLength = (byte) (payload[counter++] & 0xFF);
                    CCPoption.setLength(CCPOptionLength);
                    byte[] data = new byte[CCPOptionLength - 2];

                    for (int i = 0; i < data.length; i++) {
                        data[i] = (byte) (payload[counter++] & 0xFF);
                    }
                    CCPoption.setData(data);

                    ccpOptions.add(CCPoption);
                }

                CCPOptions[] ccpoptions = new CCPOptions[ccpOptions.size()];

                for (int i = 0; i < ccpOptions.size(); i++) {
                    ccpoptions[i] = ccpOptions.get(i);
                }

                this.CCPPayload = new CCPPacket(CCPCode, CCPIdentifier, CCPLength, ccpoptions);
                break;

            default:
                throw new CustomExceptions("Protocol 0x" + Integer.toHexString((payload[0] << 8 | payload[1]) & 0xFFFF) + " has not yet been implemented");

        }
        this.From = from;
    }

    /**
     *
     * The Ethernet payload for PPPoE is as follows:
     *
     * 1 2 3
     * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | VER |
     * TYPE | CODE | SESSION_ID |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
     * LENGTH | payload ~
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     * The VER field is four bits and MUST be set to 0x1 for this version of the
     * PPPoE specification.
     *
     * The TYPE field is four bits and MUST be set to 0x1 for this version of
     * the PPPoE specification.
     *
     * The CODE field is eight bits and is defined below for the Discovery and
     * PPP Session stages.
     *
     * The SESSION_ID field is sixteen bits. It is an unsigned value in network
     * byte order. It's value is defined below for Discovery packets. The value
     * is fixed for a given PPP session and, in fact, defines a PPP session
     * along with the Ethernet SOURCE_ADDR and DESTINATION_ADDR. A value of
     * 0xffff is reserved for future use and MUST NOT be used
     *
     * The LENGTH field is sixteen bits. The value, in network byte order,
     * indicates the length of the PPPoE payload. It does not include the length
     * of the Ethernet or PPPoE headers. Reference
     * https://tools.ietf.org/html/rfc2516
     */
    PPPoESession(PPPProtocol_Ids protocol, PPPCodes pppCodes, short session, LCPPacket options) {
        this.protocol = protocol;
        this.code = pppCodes;
        this.session_Id = session;
        this.LCPPayload = options;
        this.setLength((short) (this.getBytes().length - 6)); //exclude the headers size

    }

    PPPoESession(PPPProtocol_Ids protocol, PPPCodes pppCodes, short session, PAPPacket pap) {
        this.protocol = protocol;
        this.code = pppCodes;
        this.session_Id = session;
        this.PAPPayload = pap;
        this.setLength((short) (this.getBytes().length - 6)); //exclude the headers size
    }

    PPPoESession(PPPProtocol_Ids protocol, PPPCodes pppCodes, short session, IPCPPacket ipcp) {
        this.protocol = protocol;
        this.code = pppCodes;
        this.session_Id = session;
        this.IPCPPayload = ipcp;
        this.setLength((short) (this.getBytes().length - 6)); //exclude the headers size
    }

    public PPPCodes getCode() {
        return code;
    }

    public void setCode(PPPCodes code) {
        this.code = code;
    }

    public short getSession_Id() {
        return session_Id;
    }

    public void setSession_Id(short session_Id) {
        this.session_Id = session_Id;
    }

    public short getLength() {
        return length;
    }

    public final void setLength(short length) {
        this.length = length;
    }

    public final byte[] getBytes() {
        List<Byte> bytes = new ArrayList<>();

        bytes.add(typeAndVersion);
        bytes.add(code.getType());
        bytes.add((byte) (session_Id >> 8));
        bytes.add((byte) (session_Id));
        bytes.add((byte) (length >> 8));
        bytes.add((byte) length);

        bytes.add((byte) (protocol.getType() >> 8));
        bytes.add((byte) protocol.getType());

        switch (protocol) {
            case LCP:
                bytes.add(LCPPayload.getCode().getCode());
                bytes.add(LCPPayload.getIdentifier());

                if (LCPPayload.getCode() == LCPCodes.Echo_Reply
                        || LCPPayload.getCode() == LCPCodes.Echo_Rq
                        || LCPPayload.getCode() == LCPCodes.Terminate_Rq
                        || LCPPayload.getCode() == LCPCodes.Terminate_Ack) {

                    for (LCPOptions opt : this.LCPPayload.getPayload()) {
                        bytes.add((byte) 0); // the length is 2 bytes, those packets provide only one, that's adding one zero
                        bytes.add(opt.getLength());
                        if (opt.getData() != null) {
                            for (byte bt : opt.getData()) {
                                bytes.add(bt);
                            }
                        }
                    }

                } else {

                    bytes.add((byte) (LCPPayload.getLength() >> 8));
                    bytes.add((byte) LCPPayload.getLength());

                    for (LCPOptions opt : this.LCPPayload.getPayload()) {
                        bytes.add(opt.getType());
                        bytes.add(opt.getLength());
                        if (opt.getData() != null) {
                            for (byte bt : opt.getData()) {
                                bytes.add(bt);
                            }
                        }
                    }
                }
                break;
            case PAP:

                bytes.add(PAPPayload.getCode().getCode());
                bytes.add(PAPPayload.getIdentifier());
                bytes.add((byte) (PAPPayload.getLength() >> 8));
                bytes.add((byte) PAPPayload.getLength());
                bytes.add((byte) PAPPayload.getUserName().length);
                for (byte userNamseChar : PAPPayload.getUserName()) {
                    bytes.add(userNamseChar);
                }
                bytes.add((byte) PAPPayload.getPassword().length);
                for (byte userNamseChar : PAPPayload.getPassword()) {
                    bytes.add(userNamseChar);
                }
                break;
            case IPCP:

                bytes.add(IPCPPayload.getCode().getCode());
                bytes.add(IPCPPayload.getIdentifier());
                bytes.add((byte) (IPCPPayload.getLength() >> 8));
                bytes.add((byte) IPCPPayload.getLength());

                for (IPCPOptions option : IPCPPayload.getPayload()) {
                    bytes.add(option.getOption());
                    bytes.add(option.getLength());
                    for (byte ip : option.getIP().getAddress()) {
                        bytes.add(ip);
                    }
                }
                break;
            case CCP:

                bytes.add(CCPPayload.getCode().getCode());
                bytes.add(CCPPayload.getIdentifier());
                bytes.add((byte) (CCPPayload.getLength() >> 8));
                bytes.add((byte) CCPPayload.getLength());

                for (CCPOptions option : CCPPayload.getPayload()) {
                    bytes.add(option.getOption());
                    bytes.add(option.getLength());
                    for (byte bt : option.getData()) {
                        bytes.add(bt);
                    }
                }
                break;
        }

        byte[] ret = new byte[bytes.size()];

        for (int i = 0; i < bytes.size(); i++) {
            ret[i] = bytes.get(i);
        }

        return ret;
    }

    public PPPProtocol_Ids getProtocol() {
        return protocol;
    }

    public void setProtocol(PPPProtocol_Ids protocol) {
        this.protocol = protocol;
    }

    public LCPPacket getLCPPayload() {
        return LCPPayload;
    }

    public MACAddress getFrom() {
        return From;
    }

    public void setFrom(MACAddress From) {
        this.From = From;
    }

    public PAPPacket getPAPPayload() {
        return PAPPayload;
    }

    public void setPAPPayload(PAPPacket PAPPayload) {
        this.PAPPayload = PAPPayload;
    }

    public IPCPPacket getIPCPPayload() {
        return IPCPPayload;
    }

    public void setIPCPPayload(IPCPPacket IPCPPayload) {
        this.IPCPPayload = IPCPPayload;
    }

    public CCPPacket getCCPPayload() {
        return CCPPayload;
    }

    public void setCCPPayload(CCPPacket CCPPayload) {
        this.CCPPayload = CCPPayload;
    }

}
