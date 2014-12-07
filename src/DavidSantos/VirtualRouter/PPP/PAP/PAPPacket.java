/*
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.PPP.PAP;

///**
// *  0                   1                   2                   3
// *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// *  |     Code      |  Identifier   |            Length             |
// *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// *  | Peer-ID Length|  Peer-Id ...
// *  +-+-+-+-+-+-+-+-+-+-+-+-+
// *  | Passwd-Length |  Password  ...
// *  +-+-+-+-+-+-+-+-+-+-+-+-+-+
// *
// *  
// */
/**
 *
 *
 *
 */
public class PAPPacket {

    private PAPCodes code;
    private byte identifier;
    private short length;
    private byte[] userName;
    private byte[] password;
    private byte[] message;

    public PAPPacket(PAPCodes code, byte identifier, short length, byte[] userName, byte[] password) {
        this.code = code;
        this.identifier = identifier;
        this.length = length;
        this.userName = userName;
        this.password = password;
    }
    
    /**
     *
     * @param code
     * @param identifier
     * @param userName
     * @param password
     */
    public PAPPacket(PAPCodes code, byte identifier, String userName, String password) {
        this.code = code;
        this.identifier = identifier;
        this.length = (short) (4 + userName.length()+1+password.length()+1);
        this.userName = userName.getBytes();
        this.password = password.getBytes();
    }
    
    public PAPPacket(PAPCodes code, byte identifier, short length, byte[] message) {
        this.code = code;
        this.identifier = identifier;
        this.length = length;
        this.message = message;
    }

    public PAPCodes getCode() {
        return code;
    }

    public void setCode(PAPCodes code) {
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

    public byte[] getUserName() {
        return userName;
    }

    public void setUserName(byte[] userName) {
        this.userName = userName;
    }

    public byte[] getPassword() {
        return password;
    }

    public void setPassword(byte[] password) {
        this.password = password;
    }

    public String getMessage() {
        return new String(message);
    }

    public void setMessage(byte[] message) {
        this.message = message;
    }

}
