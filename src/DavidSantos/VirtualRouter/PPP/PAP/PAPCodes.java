/*
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.PPP.PAP;

import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;

/**
 *
 * @author root
 */
public enum PAPCodes {

    PasswordRequest((byte) 0x01),
    PasswordAck((byte) 0x02),
    PasswordNak((byte) 0x03);

    private final byte code;

    private PAPCodes(byte code) {
        this.code = code;
    }

    public static PAPCodes getCodeName(byte number) throws CustomExceptions {
        switch (number) {
            case 0x01:
                return PAPCodes.PasswordRequest;
            case 0x02:
                return PAPCodes.PasswordAck;
            case 0x03:
                return PAPCodes.PasswordNak;
            default:
                throw new CustomExceptions("PAP code unknown: " + Integer.toHexString(number));
        }
    }

    public byte getCode() {
        return code;
    }

}
