/*
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.NAT;

import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

/**
 *
 * @author root
 */
public class NetworkPacket {

    private Ip4 ip = new Ip4();
    private Udp udp = new Udp();
    private Tcp tcp = new Tcp();

    public Ip4 getIp() {
        return ip;
    }

    public void setIp(Ip4 ip) {
        this.ip = ip;
    }

    public Udp getUdp() {
        return udp;
    }

    public void setUdp(Udp udp) {
        this.udp = udp;
    }

    public Tcp getTcp() {
        return tcp;
    }

    public void setTcp(Tcp tcp) {
        this.tcp = tcp;
    }

}
