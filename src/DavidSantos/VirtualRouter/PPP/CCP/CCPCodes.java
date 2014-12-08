/*
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.PPP.CCP;

import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;

/**
 *
 * @author root
 */
public enum CCPCodes {

    RESERVED((byte) 0x00),
    Configure_Rq((byte) 0x01),
    Configure_Ack((byte) 0x02),
    Configure_Nak((byte) 0x03),
    Configure_Rej((byte) 0x04),
    Terminate_Rq((byte) 0x05),
    Terminate_Ack((byte) 0x06),
    Code_Rej((byte) 0x07);

    private final byte code;

    public byte getCode() {
        return code;
    }

    private CCPCodes(byte code) {
        this.code = code;
    }

    public static CCPCodes getCode(byte number) throws CustomExceptions {
        switch (number) {
            case 0x00:
                return CCPCodes.RESERVED;

            case 0x01:
                return CCPCodes.Configure_Rq;

            case 0x02:

                return CCPCodes.Configure_Ack;
            case 0x03:

                return CCPCodes.Configure_Nak;
            case 0x04:

                return CCPCodes.Configure_Rej;
            case 0x05:

                return CCPCodes.Terminate_Rq;
            case 0x06:

                return CCPCodes.Terminate_Ack;
            case 0x07:

                return CCPCodes.Code_Rej;

            default:
                throw new CustomExceptions("CCP Code Unknown 0x" + Integer.toHexString(number & 0xFF));
        }
    }
}
