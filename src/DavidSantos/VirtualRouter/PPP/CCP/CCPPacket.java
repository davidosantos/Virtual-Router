/*
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.PPP.CCP;


//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Code      |  Identifier   |            Length             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |    Data ...
//   +-+-+-+-+


/**
 *
 * @author root
 */
public class CCPPacket {
    private CCPCodes code;
    private byte identifier;
    private short length;
    private CCPOptions[] payload;

    public CCPPacket(CCPCodes code, byte identifier, short length, CCPOptions[] payload) {
        this.code = code;
        this.identifier = identifier;
        this.length = length;
        this.payload = payload;
    }

    public CCPCodes getCode() {
        return code;
    }

    public void setCode(CCPCodes code) {
        this.code = code;
    }

    public byte getIdentifier() {
        return identifier;
    }

    public void setIdentifier(byte identifier) {
        this.identifier = identifier;
    }

    public short getLength() {
        return length;
    }

    public void setLength(short length) {
        this.length = length;
    }

    public CCPOptions[] getPayload() {
        return payload;
    }

    public void setPayload(CCPOptions[] payload) {
        this.payload = payload;
    }

    
    
    
}
