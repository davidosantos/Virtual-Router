/* 
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.PPP.LCP;

import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;

/**
 *
 * @author root
 */
public enum LCPOptions {
//         0       RESERVED
//         1       Maximum-Receive-Unit
//         3       Authentication-Protocol
//         4       Quality-Protocol
//         5       Magic-Number
//         7       Protocol-Field-Compression
//         8       Address-and-Control-Field-Compression

    RESERVED((byte) 0x00),
    Maximum_Receive_Unit((byte) 0x01),
    Authentication_Protocol((byte) 0x03),
    Quality_Protocol((byte) 0x04),
    Magic_Number((byte) 0x05),
    Protocol_Field_Compression((byte) 0x07),
    Address_and_Control_Field_Compression((byte) 0x08);

    private final byte type;

    private byte length;
    private byte[] data;

    public byte getType() {
        return type;
    }

    public static LCPOptions getTypeName(int Number) throws CustomExceptions {
        switch (Number) {
            case 0x00:
                return LCPOptions.RESERVED;
            case 0x01:
                return LCPOptions.Maximum_Receive_Unit;
            case 0x03:
                return LCPOptions.Authentication_Protocol;
            case 0x04:
                return LCPOptions.Quality_Protocol;
            case 0x05:
                return LCPOptions.Magic_Number;
            case 0x07:
                return LCPOptions.Protocol_Field_Compression;
            case 0x08:
                return LCPOptions.Address_and_Control_Field_Compression;

            default:
                throw new CustomExceptions("LCP Option Unknown: 0x" + Integer.toHexString(Number));
        }

    }

    private LCPOptions(byte type) {
        this.type = type;

    }

    public byte getLength() {
        return length;
    }

    public void setLength(byte length) {
        this.length = length;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
        this.length =  (byte) ((byte) data.length+2); //+2 type and length
    }
}
