/*
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.NAT;

import DavidSantos.VirtualRouter.MACAddress;
import java.net.InetAddress;

/**
 *
 * @author root
 */
public class NATPacket {
    private InetAddress sourceIP;
    private InetAddress destinationIP;
    private short sourcePort;
    private short destinationPort;
    MACAddress destinationMac;
    MACAddress sourceMac;

    public NATPacket(InetAddress sourceIP, InetAddress destinationIP, short sourcePort, short destinationPort, MACAddress sourceMac , MACAddress destinationMac) {
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.sourceMac = sourceMac;
        this.destinationMac = destinationMac;
    }
    
    

    public InetAddress getSourceIP() {
        return sourceIP;
    }

    public void setSourceIP(InetAddress sourceIP) {
        this.sourceIP = sourceIP;
    }

    public InetAddress getDestinationIP() {
        return destinationIP;
    }

    public void setDestinationIP(InetAddress destinationIP) {
        this.destinationIP = destinationIP;
    }

    public short getSourcePort() {
        return sourcePort;
    }

    public void setSourcePort(short sourcePort) {
        this.sourcePort = sourcePort;
    }

    public short getDestinationPort() {
        return destinationPort;
    }

    public void setDestinationPort(short destinationPort) {
        this.destinationPort = destinationPort;
    }
    
}
