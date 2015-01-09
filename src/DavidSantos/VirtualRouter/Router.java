/* 
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter;

import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;
import DavidSantos.VirtualRouter.NAT.NATPacket;
import DavidSantos.VirtualRouter.NAT.NATTransaction;
import DavidSantos.VirtualRouter.PPP.PPPTransaction;
import DavidSantos.VirtualRouter.PPP.PPPCodes;
import DavidSantos.VirtualRouter.PPP.PPPoEDiscovery;
import DavidSantos.VirtualRouter.PPP.PPPoESession;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.wan.PPP;

/**
 *
 * @author root
 */
public class Router extends Thread implements RouterInterface {

    Ip4 ip = new Ip4();
    Tcp tcp = new Tcp();
    Udp udp = new Udp();
    Ethernet ethernet = new Ethernet();
    PPP ppp = new PPP();
    static Pcap WanPort;
    int InterfaceMTU;

    private OperatingMode opMode;

    MACAddress thisRouterWanMAC;

    private final RouterImplementation routerImpl;

    PPPTransaction pppTransaction;

    NATTransaction Nat;

    public Router(RouterImplementation routerImpl) {
        this.routerImpl = routerImpl;
        pppTransaction = new PPPTransaction(this);
        Nat = new NATTransaction(this);
        this.setName("Router");
        try {
            thisRouterWanMAC = new MACAddress(new byte[]{(byte) 0x78, (byte) 0x2B, (byte) 0xBB, (byte) 0xEE, (byte) 0x88, (byte) 0x44});
        } catch (CustomExceptions ex) {
            Logger.getLogger(Router.class.getName()).log(Level.SEVERE, null, ex);
        }

        this.opMode = OperatingMode.SingleInterface;

    }

    @Override
    public void run() {
        List<PcapIf> alldevs = new ArrayList<>(); // Will be filled with NICs  
        final StringBuilder errbuf = new StringBuilder(); // For any error msgs  

        /**
         * *************************************************************************
         * First get a list of devices on this system
         * ************************************************************************
         */
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errbuf
                    .toString());
            return;
        }

        System.out.println("Network devices found:");

        int i = 0;
        for (PcapIf device : alldevs) {
            String description
                    = (device.getDescription() != null) ? device.getDescription()
                            : "No description available";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
        }

//        final PcapIf device = alldevs.get(9); // We know we have atleast 1 device  
//        System.out
//                .printf("\nChoosing '%s' on your behalf:\n",
//                       device (device.getDescription() != null) ? device.getDescription()
//                                : device.getName());
//        
        int snaplen = 64 * 1024;           // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture packets all packet
        int timeout = 0;           // 0 seconds in millis  

        WanPort = Pcap.openLive(alldevs.get(9).getName(), snaplen, flags, timeout, errbuf);

        PcapPacketHandler<String> WanHandler;
        WanHandler = new PcapPacketHandler<String>() {

            @Override
            public void nextPacket(PcapPacket packet, String user) {

                try {

                    if (packet.hasHeader(ethernet)) {
                        ethernet = packet.getHeader(ethernet);
                    } else {
                        return;
                        //throw new CustomExceptions("No Ethernet Header for packet: \n" + packet.toHexdump());
                    }

                    MACAddress destinationRouter = new MACAddress(packet.getHeader(ethernet).destination());

                    if (thisRouterWanMAC.equals(destinationRouter)) { // only listen to packets sent to me

                        EthernetHeader ethernetHeader = new EthernetHeader(thisRouterWanMAC,
                                new MACAddress(packet.getHeader(ethernet).source()), (short) packet.getHeader(ethernet).type());

                        switch (ethernetHeader.getType()) {
                            case IPv4:
                                if (opMode == OperatingMode.SingleInterface) {
                                    if (pppTransaction.isConnected()) {
                                        //NAT must know about this, so when packet returns
                                        if (packet.hasHeader(udp) || packet.hasHeader(tcp)) {

                                            if (packet.hasHeader(udp)) {
                                                NATTransaction.addTemporaryNat(new NATPacket(
                                                        InetAddress.getByAddress(packet.getHeader(ip).source()),
                                                        InetAddress.getByAddress(packet.getHeader(ip).destination()),
                                                        (short) packet.getHeader(udp).source(),
                                                        (short) packet.getHeader(udp).destination(),
                                                        new MACAddress(packet.getHeader(ethernet).source()),
                                                        new MACAddress(packet.getHeader(ethernet).destination())));

                                            } else {

                                                NATTransaction.addTemporaryNat(new NATPacket(
                                                        InetAddress.getByAddress(packet.getHeader(ip).source()),
                                                        InetAddress.getByAddress(packet.getHeader(ip).destination()),
                                                        (short) packet.getHeader(tcp).source(),
                                                        (short) packet.getHeader(tcp).destination(),
                                                        new MACAddress(packet.getHeader(ethernet).source()),
                                                        new MACAddress(packet.getHeader(ethernet).destination())));

                                            }

                                        } else {
                                            throw new CustomExceptions("Packet has no tcp or udp header");
                                        }

                                        packet.getHeader(ip).source(pppTransaction.getIp().getAddress());
                                        //changing a packet requires to recalculate the checksum
                                        recalcuteChecksum(packet);

                                        byte[] data = new byte[packet.size() - packet.getHeader(ethernet).getLength()];
                                        int j = 0;
                                        //index i = without ethernet header
                                        for (int i = packet.getHeader(ip).getOffset(); i < packet.size(); i++, j++) {
                                            data[j] = packet.getByte(i);
                                        }

                                        pppTransaction.sendEncapsulatedData(data);

                                        routerImpl.info("sending IP packet: ");

                                    }
                                }

                                break;
                            case Arp:

                                break;
                            case PPP_Session_St:

                                byte[] payloadSession = ethernet.getPayload();
                                //    1                   2                   3
                                //    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                //   |  VER  | TYPE  |      CODE     |          SESSION_ID           |
                                //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                //   |            LENGTH             |           payload             ~
                                //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                // refer to https://tools.ietf.org/html/rfc2516
                                if (payloadSession[0] == 0x11) { //0x11 is version and type 1 and 1
                                    PPPCodes type = PPPCodes.getTypeName(payloadSession[1] & 0xFF);
                                    type.setFrom(new MACAddress(packet.getHeader(ethernet).source()));
                                    short session = twoBytesToShort(payloadSession[2], payloadSession[3]);
                                    short length = twoBytesToShort(payloadSession[4], payloadSession[5]);
                                    byte[] payloadPPPoE = new byte[length];
                                    int i = 6;
                                    for (int j = 0; j < length; j++) {
                                        payloadPPPoE[j] = (byte) (payloadSession[i++] & 0xFF);
                                    }

                                    pppTransaction.onReceive_Session_St(new PPPoESession(type, session, length, payloadPPPoE, new MACAddress(ethernet.source()), packet));

                                } else {
                                    throw new CustomExceptions("PPP Packet not supported, the only version supported is 0x11, version received is: 0x"
                                            + Integer.toHexString(payloadSession[0]));
                                }

                                break;

                            case PPP_Discovery_St:

                                byte[] payload = ethernet.getPayload();
                                //    1                   2                   3
                                //    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                //   |  VER  | TYPE  |      CODE     |          SESSION_ID           |
                                //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                //   |            LENGTH             |           payload             ~
                                //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                // refer to https://tools.ietf.org/html/rfc2516
                                if (payload[0] == 0x11) { //0x11 is version and type 1 and 1
                                    PPPCodes type = PPPCodes.getTypeName(payload[1] & 0xFF);  //1 is type                              
                                    short session = twoBytesToShort(payload[2], payload[3]); //2, 3 session
                                    short length = twoBytesToShort(payload[4], payload[5]);
                                    byte[] payloadPPPoE = new byte[length];
                                    int i = 6;
                                    for (int j = 0; j < length; j++) {
                                        payloadPPPoE[j] = (byte) (payload[i++] & 0xFF);
                                    }

                                    type.setFrom(new MACAddress(packet.getHeader(ethernet).source()));
                                    pppTransaction.onReceive_Discovery_St(new PPPoEDiscovery(type, session, length, payloadPPPoE));

                                } else {
                                    throw new CustomExceptions("PPP Packet not supported, the only version supported is 0x11, version received is: 0x"
                                            + Integer.toHexString(payload[0]));
                                }
                                break;
                            case IPv6:
                                break;

                            default:
                                throw new AssertionError(ethernetHeader.getType().name());

                        }
                    }

                } catch (CustomExceptions ex) {
                    System.err.println(ex.getMessage());
                    for (StackTraceElement element : ex.getStackTrace()) {
                        System.out.println(element);

                    }
                    routerImpl.routerErrorReport(ex.getMessage(), ex.getStackTrace());
                } catch (UnknownHostException ex) {
                    routerImpl.routerErrorReport(ex.getMessage(), ex.getStackTrace());
                }

            }
        };

        if (WanPort == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return;
        }

        WanPort.loop(0, WanHandler, "");

        WanPort.close();

    }

    private short twoBytesToShort(byte b1, byte b2) {
        return (short) ((b1 << 8) | (b2 & 0xFF));
    }

    static void send(byte[] data) {
        WanPort.sendPacket(data);
    }

    public void startRouter() {
        this.start();
    }

    public RouterInterface getRouter() {
        return this;
    }

    public void disconnect() {
        try {
            pppTransaction.disconnect();
        } catch (CustomExceptions ex) {
            routerImpl.routerErrorReport(ex.getMessage(), ex.getStackTrace());
        }
    }

    @Override
    public void sendWanEthernetBroadcast(EthernetTypes type, byte[] data) throws CustomExceptions {
        // be ware of MTU
        MACAddress dest = new MACAddress(new byte[]{(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff});
        //MACAddress source = new MACAddress(new byte[]{(byte) 0x78, (byte) 0x2b, (byte) 0xcb, (byte) 0xee, (byte) 0x4e, (byte) 0x39});
        //78:2B:CB:EE:4E:39 pc do serviço
        //00:1E:C9:23:0A:04 pc de casa
        byte[] toSend = new byte[dest.mac.length + thisRouterWanMAC.mac.length + data.length + 2];// +2 for type field
        int byteCount = 0;
        for (byte bt : dest.mac) {
            toSend[byteCount++] = bt;
        }

        for (byte bt : thisRouterWanMAC.mac) {
            toSend[byteCount++] = bt;
        }

        toSend[byteCount++] = (byte) (type.getType() >> 8);
        toSend[byteCount++] = (byte) type.getType();

        for (byte bt : data) {
            toSend[byteCount++] = bt;
        }

        WanPort.sendPacket(toSend);
    }

    @Override
    public void startPPPoEService() {
        try {

            pppTransaction.start();

        } catch (CustomExceptions ex) {
            System.out.println(ex.getMessage());
            this.routerImpl.routerErrorReport(ex.getMessage(), ex.getStackTrace());
        }
    }

    @Override
    public void sendWanData(EthernetTypes type, MACAddress to, byte[] data) throws CustomExceptions {
        // be ware of MTU
        //MACAddress source = new MACAddress(new byte[]{(byte) 0x78, (byte) 0x2B, (byte) 0xCB, (byte) 0xEE, (byte) 0x4E, (byte) 0x39});
        // MACAddress source = new MACAddress(new byte[]{(byte) 0x00, (byte) 0x1e, (byte) 0xc9, (byte) 0x23, (byte) 0x0a, (byte) 0x04});

        byte[] toSend = new byte[to.mac.length + thisRouterWanMAC.mac.length + data.length + 2];// +2 for type field
        int byteCount = 0;
        for (byte bt : to.mac) {
            toSend[byteCount++] = bt;
        }

        for (byte bt : thisRouterWanMAC.mac) {
            toSend[byteCount++] = bt;
        }

        toSend[byteCount++] = (byte) (type.getType() >> 8);
        toSend[byteCount++] = (byte) type.getType();

        for (byte bt : data) {
            toSend[byteCount++] = bt;
        }

        WanPort.sendPacket(toSend);
    }

    @Override
    public void sendLanData(PcapPacket data) {

        data.getHeader(ethernet).source(thisRouterWanMAC.mac);

        recalcuteChecksum(data);
//        byte[] dataBytes = new byte[data.size()];

//        int indexer = 0;
//
//        for (byte bt : data.getHeader(ethernet).getByteArray(data.getHeader(ethernet).getOffset(), data.getHeader(ethernet).getLength())) {
//            dataBytes[indexer++] = bt;
//        }
//
//        if (data.hasHeader(ip)) {
//            for (byte bt : data.getHeader(ip).getByteArray(data.getHeader(ip).getOffset(), data.getHeader(ip).getLength())) {
//                dataBytes[indexer++] = bt;
//            }
//        } else if (data.hasHeader(tcp)) {
//            for (byte bt : data.getHeader(tcp).getByteArray(data.getHeader(tcp).getOffset(), data.getHeader(tcp).getLength())) {
//                dataBytes[indexer++] = bt;
//            }
//        }
//        int j = 0;
//        //index i = without ethernet header
//        for (int i = data.getHeader(ip).getOffset(); i < data.size(); i++, j++) {
//            dataBytes[j] = data.getByte(i);
//        }
        ByteBuffer buf = ByteBuffer.wrap(data.getByteArray(0, data.size()));
        if (opMode == OperatingMode.SingleInterface) {
            WanPort.sendPacket(buf); // for now send through wan for tests
        }
    }

    @Override
    public String[] getPPPoEUser() {
        return routerImpl.getPPPoEUser();
    }

    @Override
    public void info(String info) {
        routerImpl.info(info);
    }

    @Override
    public String getPPPoEServiceName() {

        return routerImpl.getPPPoEServiceName();
    }

    private PcapPacket recalcuteChecksum(PcapPacket packet) {
        
        if (packet.hasHeader(ip)) {
            packet.getHeader(ip).checksum(packet.getHeader(ip).calculateChecksum());
        }
        if (packet.hasHeader(udp)) {
            //6 -> set manually the checksum, worked!
            packet.getHeader(udp).setShort(6, (short) packet.getHeader(udp).calculateChecksum());
        }
        if (packet.hasHeader(tcp)) {

            packet.getHeader(tcp).checksum(packet.getHeader(tcp).calculateChecksum());
        }
        return packet;
    }

    public OperatingMode getOpMode() {
        return opMode;
    }

    public void setOpMode(OperatingMode opMode) {
        this.opMode = opMode;
    }

    enum OperatingMode {

        SingleInterface,
        MultipleInterfaces;
    }

}
