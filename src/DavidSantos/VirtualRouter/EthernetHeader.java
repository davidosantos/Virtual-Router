/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
