/* 
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.PPP.LCP;

/**
 *
 * @author root
 */
public class LCPPacket {
    private LCPCodes code;
    private byte identifier;
    private short length;
    private LCPOptions[] payload;

    /**
     * This constructor is meant to be used when receiving LCP Packet from network.
     * @param code
     * @param identifier
     * @param length
     * @param payload
     */
    public LCPPacket(LCPCodes code, byte identifier, short length, LCPOptions[] payload) {
        this.code = code;
        this.identifier = identifier;
        this.length = length;
        this.payload = payload;
    }
    /**
     * This constructor is meant to be used when creating new packet.
     * @param code
     * @param identifier
     * @param length
     * @param payload
     */
    public LCPPacket(LCPCodes code, byte identifier, LCPOptions[] payload) {
        this.code = code;
        this.identifier = identifier;
        this.length = calculateLength(payload);
        this.payload = payload;
    }
    
    private short calculateLength(LCPOptions[] opt){
        short calculatedlength = 0;
        for(LCPOptions option :  opt){
            calculatedlength += option.getLength();
        }
        return calculatedlength += 4; // +4 for code, indentifier and length
    }
    

    public LCPCodes getCode() {
        return code;
    }

    public void setCode(LCPCodes code) {
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

    public LCPOptions[] getPayload() {
        return payload;
    }

    public void setPayload(LCPOptions[] payload) {
        this.payload = payload;
    }
    
}
