/*
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.NAT;

import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;
import DavidSantos.VirtualRouter.RouterInterface;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.packet.JBinding;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.RegistryHeaderErrors;
import org.jnetpcap.packet.annotate.Bind;
import org.jnetpcap.packet.annotate.Field;
import org.jnetpcap.packet.annotate.Header;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.wan.PPP;

/**
 *
 * @author root
 */
public class NATTransaction {

    private static final List<NATPacket> natTable = new ArrayList<>();
    private static final Ip4 ip = new Ip4();
    private static final Udp udp = new Udp();
    private static final Tcp tcp = new Tcp();
    private static final Ethernet ethernet = new Ethernet();

    private static RouterInterface routerInterface;

    public NATTransaction(RouterInterface routerInterface) {
        this.routerInterface = routerInterface;
    }

    public static void addTemporaryNat(NATPacket packet) {
        for (NATPacket natPacket : natTable) {
            if (natPacket.getSourcePort() == packet.getSourcePort()) {
                return;
            }
        }
        natTable.add(packet);
    }

    public static void addNat(NATPacket packet) {

    }

    public static void newIncoming(PcapPacket pcapPacket) throws CustomExceptions {

        short sourcePort;
        short destinationPort;
        InetAddress sourceIp;
        InetAddress destinationIp;

        if (pcapPacket.hasHeader(ip)) {
            try {
                sourceIp = InetAddress.getByAddress(pcapPacket.getHeader(ip).source());
                destinationIp = InetAddress.getByAddress(pcapPacket.getHeader(ip).destination());              
            } catch (UnknownHostException ex) {
                throw new CustomExceptions("Nat Ip error: " + ex.getMessage());
            }

        } else {
            sourceIp = null;
            destinationIp = null;
        }

        if (pcapPacket.hasHeader(udp) || pcapPacket.hasHeader(tcp)) {

            if (pcapPacket.hasHeader(udp)) {
                sourcePort = (short) pcapPacket.getHeader(udp).source();
                destinationPort = (short) pcapPacket.getHeader(udp).destination();
                
                 for (NATPacket packet : natTable) {
                    if (packet.getDestinationPort()== sourcePort) {
                        pcapPacket.getHeader(ethernet).destination(packet.sourceMac.getMac());
                        pcapPacket.getHeader(ip).destination(packet.getSourceIP().getAddress());
                        routerInterface.sendLanData(pcapPacket);
                        return;
                    }
                }
                
            } else {
                
                sourcePort = (short) pcapPacket.getHeader(tcp).source();
                destinationPort = (short) pcapPacket.getHeader(tcp).destination();
                
                for (NATPacket packet : natTable) {
                   if (packet.getDestinationPort()== sourcePort) {
                        pcapPacket.getHeader(ethernet).destination(packet.sourceMac.getMac());
                        pcapPacket.getHeader(ip).destination(packet.getSourceIP().getAddress());
                        routerInterface.sendLanData(pcapPacket);
                        return;
                    }
                }
            }

        } else {
            throw new CustomExceptions("Nat Error, Packet has no tcp or udp header");
        }

        throw new CustomExceptions("Could not find who sent Packet source port " + sourcePort + " ip " + sourceIp.toString() + " destination port " + destinationPort + " ip " + destinationIp);
    }

//    public NATPacket getNat(short sourcePort) throws CustomExceptions {
//
//    }
}
