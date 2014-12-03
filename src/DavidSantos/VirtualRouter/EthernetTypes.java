/* 
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter;

import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;

/**
 *
 * @author root
 */
public enum EthernetTypes {

    IPv4((short) 0x0800),
    Arp((short) 0x0806),
    PPP_Discovery_St((short) 0x8863),
    PPP_Session_St((short) 0x8864),
    IPv6((short) 0x8864);

    private final short type;

    public short getType() {
        return type;
    }

    public static EthernetTypes getTypeName(int Number) throws CustomExceptions {
        switch (Number) {
            case 0x0800:
                return EthernetTypes.IPv4;
            case 0x0806:
                return EthernetTypes.Arp;
            case 0x8863:
                return EthernetTypes.PPP_Discovery_St;
            case 0x8864:
                return EthernetTypes.PPP_Session_St;
            case 0x86dd:
                return EthernetTypes.IPv6;

            default:
                throw new CustomExceptions("Ethernet Type Unknown: 0x" + Integer.toHexString(Number));
        }

    }

    private EthernetTypes(short type) {
        this.type = type;
    }
}
