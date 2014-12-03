/* 
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.DNS;

import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;
import DavidSantos.VirtualRouter.Ports.Ports;
import DavidSantos.VirtualRouter.TransactionListener;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author root
 */
public class DNSTransaction extends TransactionListener {

    private final DNSImplementation DNSImpl;

    boolean redirect = true;

    InetAddress NetworkInterface;

    public DNSTransaction(DNSImplementation DNSImpl, InetAddress NetworkInterface) {
        super(DNSImpl.getDNSServerAdrss(), Ports.PortsNumber.Port_DNS, TransactionListener.ConnectionType.Both);//not tcp
        this.DNSImpl = DNSImpl;
        this.NetworkInterface = NetworkInterface;

    }

    public void startService() {
        super.start();

    }

    @Override
    public void onTCPConnectionReceived(Socket socket) {
        try {
            byte[] data;
            InputStream input = socket.getInputStream();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte buffer[] = new byte[10];
            input.skip(2); // skip the size value
            int s;
            while ((s = input.read(buffer)) != -1) {
                baos.write(buffer, 0, s);
            }
            data = Ports.Shrink.getShrikedData(baos.toByteArray());

            DNSPacket Client = new DNSPacket();
            try {
                Client.initPacket(data);
            } catch (AssertionError ex) {
                Logger.getLogger(DNSTransaction.class.getName()).log(Level.SEVERE, null, ex);
            } catch (CustomExceptions ex) {
                Logger.getLogger(DNSTransaction.class.getName()).log(Level.SEVERE, null, ex);
                DNSImpl.DNSOIExcetion("TCP DNS Packet: " + ex.getMessage());
            }
            short clientDNS_Id = Client.getQuery_Id();

            if (Client.isIsInitiated()) {
                for (DNSPacket.Questions questions : Client.getDataOfQuestions()) {
                    if (this.DNSImpl.allowDNSRequest("TCP: " + socket.getInetAddress().getHostAddress(), questions.name)) {

                        try {

                            byte[] response = Ports.receiveTCPData(data, Ports.Timeout.TenSecs, NetworkInterface, DNSImpl.getDNSServerAdrssToRedirect(), Ports.PortsNumber.Port_DNS);

                            DNSPacket packetToClient = new DNSPacket();

                            try {
                                packetToClient.initPacket(response);
                            } catch (AssertionError ex) {
                                Logger.getLogger(DNSTransaction.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (CustomExceptions ex) {
                                Logger.getLogger(DNSTransaction.class.getName()).log(Level.SEVERE, null, ex);
                                DNSImpl.DNSOIExcetion("DNS Packet Received from outside" + ex.getMessage());
                            }
                            packetToClient.setQuery_Id(clientDNS_Id);

                            socket.getOutputStream().write(packetToClient.getData());

                        } catch (IOException ex) {
                            this.DNSImpl.DNSOIExcetion(ex.getMessage());
                        }

                    } else {

                        if (DNSImpl.getDNSShowIRedirectDiniedRequests()) {
                            InetAddress AddrsToGo = DNSImpl.getDNSDiniedRequestsShouldBeRedirectedTo();

                            DNSPacket pktToSend = new DNSPacket();

                            try {
                                pktToSend.initPacket(pktToSend.createNewPacketAsnwer(Client.getData(), AddrsToGo));
                            } catch (AssertionError ex) {
                                Logger.getLogger(DNSTransaction.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (CustomExceptions ex) {
                                Logger.getLogger(DNSTransaction.class.getName()).log(Level.SEVERE, null, ex);
                                DNSImpl.DNSOIExcetion("Error creating new DNS Packet for Deined " + socket.getInetAddress().getHostName() + ": " + ex.getMessage());
                            }

                            try {

                                socket.getOutputStream().write(pktToSend.getData());
                            } catch (IOException ex) {
                                this.DNSImpl.DNSOIExcetion(ex.getMessage());
                            }

                        } else {

                            Client.SetErrorCode(DNSPacket.ErrorCode.QryRefused);
                            Client.setQuestionOrResponse(false); //response

                            try {
                                socket.getOutputStream().write(Client.getData());
                            } catch (IOException ex) {
                                this.DNSImpl.DNSOIExcetion(ex.getMessage());
                            }
                        }
                    }
                }
            }

        } catch (IOException ex) {
            Logger.getLogger(DNSTransaction.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    @Override
    public void onUDPConnectionReceived(DatagramPacket packet, DatagramSocket UDPSocket) {

        DNSPacket Client = new DNSPacket();
        try {
            Client.initPacket(Ports.Shrink.getShrikedData(packet.getData()));
        } catch (AssertionError ex) {
            Logger.getLogger(DNSTransaction.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CustomExceptions ex) {
            Logger.getLogger(DNSTransaction.class.getName()).log(Level.SEVERE, null, ex);
            DNSImpl.DNSOIExcetion("UDP DNS Packet: " + ex.getMessage());
        }
        InetAddress ClientAddrs = packet.getAddress();
        int ClientPort = packet.getPort();

        if (Client.isIsInitiated()) {
            for (DNSPacket.Questions questions : Client.getDataOfQuestions()) {
                if (this.DNSImpl.allowDNSRequest(packet.getAddress().getHostAddress(), questions.name)) {

                    try {
                        packet.setAddress(DNSImpl.getDNSServerAdrssToRedirect());
                        packet.setPort(Ports.PortsNumber.Port_DNS.getPortInt());
                        DatagramPacket response = Ports.sendAndReceiveUDPData(NetworkInterface, Ports.Timeout.TenSecs, packet);

                        UDPSocket.send(new DatagramPacket(response.getData(), response.getData().length, ClientAddrs, ClientPort));

                    } catch (IOException ex) {
                        this.DNSImpl.DNSOIExcetion(ex.getMessage());
                    }

                } else {

                    if (DNSImpl.getDNSShowIRedirectDiniedRequests()) {
                        InetAddress AddrsToGo = DNSImpl.getDNSDiniedRequestsShouldBeRedirectedTo();

                        DNSPacket pktToSend = new DNSPacket();

                        try {
                            pktToSend.initPacket(pktToSend.createNewPacketAsnwer(Client.getData(), AddrsToGo));
                        } catch (AssertionError ex) {
                            Logger.getLogger(DNSTransaction.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (CustomExceptions ex) {
                            Logger.getLogger(DNSTransaction.class.getName()).log(Level.SEVERE, null, ex);
                            DNSImpl.DNSOIExcetion("Error creating new DNS Packet for Deined " + ClientAddrs.getHostName() + ": " + ex.getMessage());
                        } catch (IOException ex) {
                            Logger.getLogger(DNSTransaction.class.getName()).log(Level.SEVERE, null, ex);
                        }

                        try {

                            UDPSocket.send(new DatagramPacket(pktToSend.getData(), pktToSend.getData().length, ClientAddrs, ClientPort));
                        } catch (IOException ex) {
                            this.DNSImpl.DNSOIExcetion(ex.getMessage());
                        }

                    } else {

                        Client.SetErrorCode(DNSPacket.ErrorCode.QryRefused);
                        Client.setQuestionOrResponse(false); //response

                        try {
                            UDPSocket.send(new DatagramPacket(Client.getData(), Client.getData().length, ClientAddrs, ClientPort));
                        } catch (IOException ex) {
                            this.DNSImpl.DNSOIExcetion(ex.getMessage());
                        }
                    }
                }
            }
        }

    }

    @Override
    public String setTransactionName() {
        return "DNS Server";
    }

}
