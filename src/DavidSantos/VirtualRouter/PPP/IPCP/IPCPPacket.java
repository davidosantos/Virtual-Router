/*
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */

package DavidSantos.VirtualRouter.PPP.IPCP;

/**
 *
 * @author root
 */
public class IPCPPacket {
    private IPCPCodes code;
    private byte identifier;
    private short length;
    private IPCPOptions payload[];

    public IPCPPacket(IPCPCodes code, byte identifier, short length, IPCPOptions[] payload) {
        this.code = code;
        this.identifier = identifier;
        this.length = length;
        this.payload = payload;
    }

    public IPCPPacket(IPCPCodes code, byte identifier, IPCPOptions[] payload) {
        this.code = code;
        this.identifier = identifier;
        this.payload = payload;
        this.length = getCalculatedLength();
    }
    
    private short getCalculatedLength(){
        short bytes = 4;
        for(IPCPOptions option : this.payload){
            bytes += 2; //Option type and length filds are two bytes
            bytes += option.getIP().getAddress().length;
        }
        return bytes;
    }

    public IPCPCodes getCode() {
        return code;
    }

    public void setCode(IPCPCodes code) {
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

    public IPCPOptions[] getPayload() {
        return payload;
    }

    public void setPayload(IPCPOptions[] payload) {
        this.payload = payload;
    }
}
