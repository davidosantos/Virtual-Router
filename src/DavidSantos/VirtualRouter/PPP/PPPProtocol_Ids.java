/* 
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.PPP;

import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;

/**
 *
 * @author root
 */
public enum PPPProtocol_Ids {

//     0001            Padding Protocol
//      0003 to 001f    reserved (transparency inefficient)
//      007d            reserved (Control Escape)
//      00cf            reserved (PPP NLPID)
//      00ff            reserved (compression inefficient)
//
//      8001 to 801f    unused
//      807d            unused
//      80cf            unused
//      80ff            unused
//
//      c021            Link Control Protocol
//      c023            Password Authentication Protocol
//      c025            Link Quality Report
//      c223            Challenge Handshake Authentication Protocol
    Padding((short) 0xc001),
    LCP((short) 0xc021),
    PAP((short) 0xc023),
    LQR((short) 0xc025),
    CHAP((short) 0xc223),
    IPv4((short) 0x0021);

    private final short protocol;

    public short getType() {
        return protocol;
    }

    public static PPPProtocol_Ids getTypeName(int Number) throws CustomExceptions {

        switch (Number) {
            case 0xc021:
                return PPPProtocol_Ids.LCP;

            default:
                throw new CustomExceptions("PPP Protocol Unknown: 0x" + Integer.toHexString(Number));
        }

    }

    private PPPProtocol_Ids(short protocol) {
        this.protocol = protocol;

    }

}
