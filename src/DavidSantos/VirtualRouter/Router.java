/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package DavidSantos.VirtualRouter;

import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;
import DavidSantos.VirtualRouter.PPP.PPPTransaction;
import DavidSantos.VirtualRouter.PPP.PPPCodes;
import DavidSantos.VirtualRouter.PPP.PPPoEDiscovery;
import java.util.ArrayList;
import java.util.List;
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

    PPPTransaction pppTransaction;

    public Router() {
        pppTransaction = new PPPTransaction(this);
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
                        throw new CustomExceptions("No Ethernet Header for packet: \n" + packet.toHexdump());
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
                            break;

                        case PPP_Discovery_St:

                            System.out.println("PPP_Discovery_St");

                            byte[] payload = ethernet.getPayload();

                            System.out.println("Erray: ");
                            int count = 0;
                            for (byte tb : payload) {
                                System.out.println(count++ + ":" + Integer.toHexString(tb & 0xFF));
                            }

//    1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  VER  | TYPE  |      CODE     |          SESSION_ID           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |            LENGTH             |           payload             ~
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                            // refer to https://tools.ietf.org/html/rfc2516
                            if (payload[0] == 0x11) { //0x11 is version and type 1 and 1
                                PPPCodes type = PPPCodes.getTypeName(payload[1] & 0xFF);
                                type.setFrom(new MACAddress(packet.getHeader(ethernet).source()));
                                short session = (short) ((short) payload[2] & 0xFF << 8 | payload[3] & 0xFF);
                                short length = (short) ((short) payload[4] & 0xFF << 8 | payload[5] & 0xFF);
                                byte[] payloadPPPoE = new byte[length];
                                int i = 6;
                                for (int j = 0; j < length; j++) {
                                    payloadPPPoE[j] = (byte) (payload[i++] & 0xFF);
                                }
                                pppTransaction.onReceive_Discovery_St(new PPPoEDiscovery(type, session, length, payloadPPPoE));

                            } else {
                                throw new CustomExceptions("PPP Packet not supported, the only version supported is 0x11, version received is: 0x"
                                        + Integer.toHexString(payload[0]));
                            }
                            break;

                        default:
                            throw new AssertionError(ethernetHeader.getType().name());

                    }

                } catch (CustomExceptions ex) {
                    System.out.println(ex.getMessage());
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

    static void send(byte[] data) {
        WanPort.sendPacket(data);
    }

    public void startRouter() {
        this.start();
    }

    public RouterInterface getRouter() {
        return this;
    }

    @Override
    public void sendWanEthernetBroadcast(EthernetTypes type, byte[] data) throws CustomExceptions {
        // be ware of MTU
        MACAddress dest = new MACAddress(new byte[]{(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff});
        MACAddress source = new MACAddress(new byte[]{(byte) 0x78, (byte) 0x2B, (byte) 0xCB, (byte) 0xEE, (byte) 0x4E, (byte) 0x39});
        //78:2B:CB:EE:4E:39 pc do serviço
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
     pppTransaction.start();
    }

    @Override
    public void sendWanData(EthernetTypes type, MACAddress to, byte[] data) throws CustomExceptions {
         // be ware of MTU
        MACAddress source = new MACAddress(new byte[]{(byte) 0x78, (byte) 0x2B, (byte) 0xCB, (byte) 0xEE, (byte) 0x4E, (byte) 0x39});

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
}
