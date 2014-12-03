/* 
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.PPP;

import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;
import DavidSantos.VirtualRouter.MACAddress;

/**
 *
 * @author root
 */
public enum PPPCodes {

    Session_Data((byte) 0x00),
    PADI((byte) 0x09),
    PADO((byte) 0x07),
    PADR((byte) 0x19),
    PADS((byte) 0x65),
    PADT((byte) 0xa7);

    private final byte type;
    private MACAddress From;

    public byte getType() {
        return type;
    }

    public static PPPCodes getTypeName(int Number) throws CustomExceptions {
     
        switch (Number) {
            case 0x00:
                return PPPCodes.Session_Data;
            case 0x09:
                return PPPCodes.PADI;
            case 0x07:
                return PPPCodes.PADO;
            case 0x19:
                return PPPCodes.PADR;
            case 0x65:
                return PPPCodes.PADS;
            case 0xa7:
                return PPPCodes.PADT;

            default:
                throw new CustomExceptions("PPP Type Unknown: 0x" + Integer.toHexString(Number));
        }

    }

    private PPPCodes(byte type) {
        this.type = type;

    }

    public MACAddress getFrom() {
        return From;
    }

    public void setFrom(MACAddress From) {
        this.From = From;
    }

}
