/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package DavidSantos.VirtualRouter.PPP;

import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;
import DavidSantos.VirtualRouter.PPP.LCP.LCPCodes;
import DavidSantos.VirtualRouter.PPP.LCP.LCPOptions;
import DavidSantos.VirtualRouter.PPP.LCP.LCPPacket;
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

    private LCPPacket LCPPayload;

    public PPPoESession(PPPCodes code, short session_Id, short length, byte[] payload) throws CustomExceptions {

        this.code = code;
        this.session_Id = session_Id;
        this.length = length;
        int counter = 0;
        this.protocol = PPPProtocol_Ids.getTypeName((short) (payload[counter++] << 8 | payload[counter++]) & 0xFFFF);
        
        switch (protocol) {
            case LCP:
                LCPCodes LCPCode = LCPCodes.getCode(payload[counter++]);
                byte LCPIdentifier = payload[counter++];
                short LCPLength = (short) (payload[counter++] << 8 | payload[counter++]);

                List<LCPOptions> LCPOpt = new ArrayList<>();

                for (int i = counter; i < payload.length;) {
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Type      |    Length     |      Maximum-Receive-Unit     |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//
//   Type 
//
//      1 byte
//
//   Length
//
//      1 byte
                    LCPOptions option = LCPOptions.getTypeName(payload[i++]);
                    option.setLength(payload[i++]);
                    option.setData(new byte[option.getLength()]);

                    for (int j = 0; j < option.getLength(); j++) {
                        option.getData()[j] = (byte) (payload[i++] & 0xFF);
                    }

                    LCPOpt.add(option);
                }

                LCPOptions[] LCPvalues = new LCPOptions[LCPOpt.size()];

                for (int i = 0; i < LCPOpt.size(); i++) {
                    LCPvalues[i] = LCPOpt.get(i);
                }

                LCPPayload = new LCPPacket(LCPCode, LCPIdentifier, LCPLength, LCPvalues);

                break;
            default:
                throw new CustomExceptions("Protocol 0x" + Integer.toHexString((payload[0] << 8 | payload[1])) + " has not yet been implemented");

        }

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
        
        bytes.add((byte)(protocol.getType() >> 8));
        bytes.add((byte)protocol.getType());
        
        bytes.add(LCPPayload.getCode().getCode());
        bytes.add(LCPPayload.getIdentifier());
        bytes.add((byte)(LCPPayload.getLength() >> 8));
        bytes.add((byte)LCPPayload.getLength());
        
        for ( LCPOptions opt : this.LCPPayload.getPayload()){
            bytes.add(opt.getType());
            bytes.add(opt.getLength());
            if (opt.getData() != null) {
                for (byte bt : opt.getData()) {
                    bytes.add(bt);
                }
            }
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

}
