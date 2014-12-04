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
public enum AuthenticationType {
    
    CHAP((short) 0xC223),	
    EAP((short) 0xC227),
    PAP((short) 0xC023);	

    private final short type;

    public short getType() {
        return type;
    }

    public static AuthenticationType getTypeName(int Number) throws CustomExceptions {
        switch (Number) {
            case 0xC223:
                return AuthenticationType.CHAP;
            case 0xC023:
                return AuthenticationType.PAP;
            case 0xC227:
                return AuthenticationType.PAP;
            

            default:
                throw new CustomExceptions("Authentication Type Unknown: 0x" + Integer.toHexString(Number));
        }

    }

    private AuthenticationType(short type) {
        this.type = type;

    }

}
