/* 
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter;

import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;
import DavidSantos.VirtualRouter.PPP.PPPTransaction;
import DavidSantos.VirtualRouter.PPP.PPPCodes;
import DavidSantos.VirtualRouter.PPP.PPPoEDiscovery;
import DavidSantos.VirtualRouter.PPP.PPPoESession;
import java.net.UnknownHostException;
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
import org.jnetpcap.protocol.wan.PPP;

/**
 *
 * @author root
 */
public class Router extends Thread implements RouterInterface {

    Ip4 ip = new Ip4();
    Tcp tcp = new Tcp();
    Ethernet ethernet = new Ethernet();
    PPP ppp = new PPP();
    static Pcap WanPort;
    int InterfaceMTU;

    private final RouterImplementation routerImpl;

    PPPTransaction pppTransaction;

    public Router(RouterImplementation routerImpl) {
        this.routerImpl = routerImpl;
        pppTransaction = new PPPTransaction(this);
        this.setName("Router");
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
        int flags = Pcap.MODE_PROMISCUOUS; // capture packets  sent to me
        int timeout = 0;           // 10 seconds in millis  

        WanPort = Pcap.openLive("eth0", snaplen, flags, timeout, errbuf);

        /**
         * *************************************************************************
         * Second we open up the selected device
         * ************************************************************************
         */
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

            @Override
            public void nextPacket(PcapPacket packet, String user) {

                try {

                    if (packet.hasHeader(ethernet)) {
                        ethernet = packet.getHeader(ethernet);
                    } else {
                        return;
                        //throw new CustomExceptions("No Ethernet Header for packet: \n" + packet.toHexdump());
                    }

                    EthernetHeader ethernetHeader = new EthernetHeader(new MACAddress(packet.getHeader(ethernet).destination()),
                            new MACAddress(packet.getHeader(ethernet).source()), (short) packet.getHeader(ethernet).type());
                    //System.out.println("Packet Type: " + ethernetHeader.getType().name());

                    switch (ethernetHeader.getType()) {
                        case IPv4:

//                            //Ethernet II, Src: a0:f3:c1:dd:c0:c4 
//                            packet.getHeader(ethernet).destination(new byte[]{
//                                (byte) 0xa0,
//                                (byte) 0xf3,
//                                (byte) 0xc1,
//                                (byte) 0xdd,
//                                (byte) 0xc0,
//                                (byte) 0xc4,});
//
//                            //00:1F:3C:21:5C:C6
//                            packet.getHeader(ethernet).source(new byte[]{
//                                (byte) 0x00,
//                                (byte) 0x1f,
//                                (byte) 0x3c,
//                                (byte) 0x21,
//                                (byte) 0x5c,
//                                (byte) 0xc6,});
                            //packet.getHeader(ip).source(InetAddress.getByName("192.168.0.104").getAddress());
                            //System.out.println("IP to: " + InetAddress.getByAddress(packet.getHeader(new Ip4()).destination()).toString());
                            //System.out.println("IP from: " + InetAddress.getByAddress(packet.getHeader(new Ip4()).source()).toString());
                            //pcap.sendPacket(packet.getByteArray(0, packet.size()));
                            break;
                        case Arp:

                            break;
                        case PPP_Session_St:

                            byte[] payloadSession = ethernet.getPayload();

//                            System.out.println("Erray: ");
//                            int count_Session = 0;
//                            for (byte tb : payloadSession) {
//                                System.out.println(count_Session++ + ":" + Integer.toHexString(tb & 0xFF));
//                            }
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
                                pppTransaction.onReceive_Session_St(new PPPoESession(type, session, length, payloadPPPoE, new MACAddress(ethernet.source())));

                            } else {
                                throw new CustomExceptions("PPP Packet not supported, the only version supported is 0x11, version received is: 0x"
                                        + Integer.toHexString(payloadSession[0]));
                            }

                            break;

                        case PPP_Discovery_St:

                            byte[] payload = ethernet.getPayload();

//                            System.out.println("Erray: ");
//                            int count = 0;
//                            for (byte tb : payload) {
//                                System.out.println(count++ + ":" + Integer.toHexString(tb & 0xFF));
//                            }
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

        WanPort.loop(0, jpacketHandler, "");

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
    
    public void disconnect(){
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
        MACAddress source = new MACAddress(new byte[]{(byte) 0x78, (byte) 0x2b, (byte) 0xcb, (byte) 0xee, (byte) 0x4e, (byte) 0x39});
        //78:2B:CB:EE:4E:39 pc do serviço
        //00:1E:C9:23:0A:04 pc de casa
        byte[] toSend = new byte[dest.mac.length + source.mac.length + data.length + 2];// +2 for type field
        int byteCount = 0;
        for (byte bt : dest.mac) {
            toSend[byteCount++] = bt;
        }

        for (byte bt : source.mac) {
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
        MACAddress source = new MACAddress(new byte[]{(byte) 0x78, (byte) 0x2B, (byte) 0xCB, (byte) 0xEE, (byte) 0x4E, (byte) 0x39});
        //MACAddress source = new MACAddress(new byte[]{(byte) 0x00, (byte) 0x1e, (byte) 0xc9, (byte) 0x23, (byte) 0x0a, (byte) 0x04});

        byte[] toSend = new byte[to.mac.length + source.mac.length + data.length + 2];// +2 for type field
        int byteCount = 0;
        for (byte bt : to.mac) {
            toSend[byteCount++] = bt;
        }

        for (byte bt : source.mac) {
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
    public String[] getPPPoEUser() {
        return routerImpl.getPPPoEUser();
    }

    public void sendBytes() {
        try {
            pppTransaction.sendEncapsulatedData(new byte[]{(byte) 0x45, (byte) 0x00, (byte) 0x00, (byte) 0x33, (byte) 0xa4, (byte) 0xb6, (byte) 0x40, (byte) 0x00, (byte) 0x40, (byte) 0x11, (byte) 0xee, (byte) 0x06, (byte) 0xc0, (byte) 0xa8, (byte) 0x00, (byte) 0x12, (byte) 0xac, (byte) 0x1b, (byte) 0x3b, (byte) 0x27, (byte) 0xe1, (byte) 0xe7, (byte) 0x00, (byte) 0x35, (byte) 0x00, (byte) 0x1f, (byte) 0xac, (byte) 0x2f, (byte) 0xeb, (byte) 0x29, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x05, (byte) 0x6c, (byte) 0x6f, (byte) 0x63, (byte) 0x61, (byte) 0x6c, (byte) 0x00, (byte) 0x00, (byte) 0x06, (byte) 0x00, (byte) 0x01});
        } catch (CustomExceptions ex) {
            Logger.getLogger(Router.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public void info(String info) {
        routerImpl.info(info);
    }

}
