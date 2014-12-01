/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package DavidSantos.VirtualRouter.PPP;

import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author root
 */
public class PPPoEDiscovery {

    private final byte typeAndVersion = 0x11;//the only version and type supported
    private PPPCodes code;
    private short session_Id;
    private short length;
    private TAGS[] payload;

    public PPPoEDiscovery(PPPCodes code, short session_Id, short length, byte[] payload) throws CustomExceptions {

        this.code = code;
        this.session_Id = session_Id;
        this.length = length;
        List<TAGS> tags = new ArrayList<>();

        for (int i = 0; i < payload.length;) {

            //    1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |          TAG_TYPE             |        TAG_LENGTH             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |          TAG_VALUE ...                                        ~
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            TAGS tg = TAGS.getTypeName((payload[i++]) << 8 | payload[i++]);
            tg.setLength((short) (int) ((payload[i++]) << 8 | payload[i++]));
            tg.setData(new byte[tg.getLength()]);

            for (int j = 0; j < tg.getLength(); j++) {
                tg.getData()[j] = (byte) (payload[i++] & 0xFF);
            }

            tags.add(tg);

        }

        this.payload = new TAGS[tags.size()];

        for (int i = 0; i < tags.size(); i++) {
            this.payload[i] = tags.get(i);
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
     * of the Ethernet or PPPoE headers.
     * Reference https://tools.ietf.org/html/rfc2516
     */
    PPPoEDiscovery(PPPCodes pppCodes, short session, TAGS[] tag) {
        this.code = pppCodes;
        this.session_Id = session;
        this.payload = tag;
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

    public TAGS[] getPayload() {
        return payload;
    }

    public void setPayload(TAGS[] payload) {
        this.payload = payload;
    }

    public final byte[] getBytes() {
        List<Byte> bytes = new ArrayList<>();

        bytes.add(typeAndVersion);
        bytes.add(code.getType());
        bytes.add((byte) (session_Id >> 8));
        bytes.add((byte) (session_Id));
        bytes.add((byte) (length >> 8));
        bytes.add((byte) length);

        for (TAGS tag : payload) {
            bytes.add((byte) (tag.getType() >> 8));
            bytes.add((byte) tag.getType());
            bytes.add((byte) (tag.getLength() >> 8));
            bytes.add((byte) tag.getLength());
            if (tag.getData() != null) {
                for (byte bt : tag.getData()) {
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

}
