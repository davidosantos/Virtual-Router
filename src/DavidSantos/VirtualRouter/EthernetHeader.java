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
public class EthernetHeader {

    private final MACAddress dest;
    private final MACAddress source;
    private final EthernetTypes Type;

    public EthernetHeader(MACAddress dest, MACAddress source, short Type) throws CustomExceptions {
        this.dest = dest;
        this.source = source;
        this.Type = EthernetTypes.getTypeName(Type & 0xFFFF);
    }

    public MACAddress getDest() {
        return dest;
    }

    public MACAddress getSource() {
        return source;
    }

    public EthernetTypes getType() {
        return Type;
    }

}
