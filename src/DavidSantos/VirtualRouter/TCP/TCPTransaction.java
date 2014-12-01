/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package DavidSantos.VirtualRouter.TCP;

import DavidSantos.VirtualRouter.EthernetHeader;
import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;
import DavidSantos.VirtualRouter.MACAddress;
import java.io.IOException;
import java.io.Serializable;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import jpcap.JpcapCaptor;

import jpcap.NetworkInterface;
import jpcap.PacketReceiver;
import jpcap.packet.DatalinkPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapDLT;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.wan.PPP;

/**
 *
 * @author root
 */
public class TCPTransaction extends Thread {

    int InterfaceMTU;

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

        final PcapIf device = alldevs.get(9); // We know we have atleast 1 device  
        System.out
                .printf("\nChoosing '%s' on your behalf:\n",
                        (device.getDescription() != null) ? device.getDescription()
                                : device.getName());
        
        
            int snaplen = 64 * 1024;           // Capture all packets, no trucation  
            int flags = Pcap.MODE_PROMISCUOUS; // capture packets  sent to me
            int timeout = 0;           // 10 seconds in millis  

            final Pcap pcap = Pcap.openLive("eth0", snaplen, flags, timeout, errbuf);

        /**
         * *************************************************************************
         * Second we open up the selected device
         * ************************************************************************
         */
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
            
           
            @Override
            public void nextPacket(PcapPacket packet, String user) {
                
                try {
                    EthernetHeader ethernetHeader = new EthernetHeader(new MACAddress(packet.getByteArray(0, 5)), new MACAddress(packet.getByteArray(6, 11)), (short) ((short) packet.getUByte(12)<< 8 | packet.getByte(13)));
                    System.out.println("TY: " + ethernetHeader.getType().name());
                
                } catch (CustomExceptions ex) {
                    System.out.println(ex.getMessage());
                }
                
                
                
                
                
                
                Ip4 ip = new Ip4();
                Tcp tcp = new Tcp();
                Ethernet ethernet = packet.getHeader(new Ethernet());
                PPP ppp = new PPP();
                
                
                System.out.println("Erray: ");
                
                for(byte tb : packet.getByteArray(0, packet.size())){
                    System.out.print(" - " + Integer.toHexString(tb & 0xFF));
                }
                System.out.println("");
                System.out.println("");
                System.out.println("");
                System.out.println("");
                System.out.println("");
                System.out.println("");
                System.out.println("");
                
                if(packet.hasHeader(ppp)){
                    System.out.println("Has ppp header");
                 
                }
                
                
                try {
                    if (packet.hasHeader(ip) && packet.hasHeader(tcp)) {
                        packet.getHeader(ethernet);
                        if (Arrays.equals(ethernet.destination(), device.getHardwareAddress())) {
                            try {
                                InetAddress inet = InetAddress.getByAddress("", packet.getHeader(ip).destination());
                                InetAddress inets = InetAddress.getByAddress("", packet.getHeader(ip).source());

                                packet.getHeader(new org.jnetpcap.protocol.wan.PPP());
                                
                                
                                
                              

                                System.out.println("Ip.dst: " + inet.toString() + " Ip.src: " + inets.toString() + " Port: " + tcp.destination());
                            } catch (UnknownHostException ex) {
                                Logger.getLogger(TCPTransaction.class.getName()).log(Level.SEVERE, null, ex);
                            }
                        }
                    }
                } catch (IOException ex) {
                    Logger.getLogger(TCPTransaction.class.getName()).log(Level.SEVERE, null, ex);
                }

            }
        };

        try {

            PcapBpfProgram filter = new PcapBpfProgram();
            String expression;
            String MACAddrs = String.format("%02x:%02x:%02x:%02x:%02x:%02x",
                    (byte) device.getHardwareAddress()[0],
                    (byte) device.getHardwareAddress()[1],
                    (byte) device.getHardwareAddress()[2],
                    (byte) device.getHardwareAddress()[3],
                    (byte) device.getHardwareAddress()[4],
                    (byte) device.getHardwareAddress()[5]);

            expression = "ether dst " + MACAddrs;

            int optimize = 0; // 1 means true, 0 means false   
            int netmask = 0;

           // int result = pcap.compile(filter, expression, optimize, netmask);

           // if (result != Pcap.OK) {
           //     System.out.println("Filter error: " + pcap.getErr());
            //    return;
            //}
            //pcap.setFilter(filter);

            if (pcap == null) {
                System.err.printf("Error while opening device for capture: "
                        + errbuf.toString());
                return;
            }

            pcap.loop(0, jpacketHandler, MACAddrs);

            pcap.close();
        } catch (IOException ex) {
            Logger.getLogger(TCPTransaction.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

}
