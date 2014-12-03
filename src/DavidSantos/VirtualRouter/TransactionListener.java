/* 
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter;

import DavidSantos.VirtualRouter.Ports.Ports;
import DavidSantos.VirtualRouter.Ports.Ports.PortsNumber;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author root
 */
public abstract class TransactionListener extends Thread {

    InetAddress adrss;
    PortsNumber port;
    ServerSocket server;
    DatagramSocket UDPSocket;
    ConnectionType connType;

    public enum ConnectionType {

        TCP,
        UDP,
        Both;
    }

    public TransactionListener(InetAddress adrss, PortsNumber port, ConnectionType connType) {
        this.adrss = adrss;
        this.port = port;
        this.connType = connType;

    }

    @Override
    public void run() {
        this.setName(setTransactionName());
        try {

            if (connType == ConnectionType.Both) {
                Runnable udp = new Runnable() {
                    @Override
                    public void run() {
                        try {
                         UDPSocket = Ports.getUDPSocket(adrss, port);
                            while (true) {
                                final DatagramPacket updPacket = new DatagramPacket(new byte[1450], 1450);

                                Runnable onConnectionThread = new Runnable() {
                                    @Override
                                    public void run() {
                                        onUDPConnectionReceived(updPacket, UDPSocket);
                                    }
                                };

                                Thread connectionProcess = new Thread(onConnectionThread);
                                UDPSocket.receive(updPacket);
                                connectionProcess.start();
                            }
                        } catch (IOException ex) {
                            Logger.getLogger(TransactionListener.class.getName()).log(Level.SEVERE, null, ex);
                        }

                    }
                };

                Runnable tcp = new Runnable() {
                    @Override
                    public void run() {
                        try {
                            server = new ServerSocket(port.getPortInt(), 1, adrss);
                            while (true) {
                                final Socket socket;
                                socket = server.accept();

                                Runnable onConnectionThread = new Runnable() {
                                    @Override
                                    public void run() {
                                        onTCPConnectionReceived(socket);
                                    }
                                };

                                Thread connectionProcess = new Thread(onConnectionThread);
                                connectionProcess.start();

                            }
                        } catch (IOException ex) {
                            Logger.getLogger(TransactionListener.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                };
                Thread thread_TCP = new Thread(tcp);
                Thread thread_UDP = new Thread(udp);
                thread_TCP.setName(this.getName() + " TCP on port: " + port.getPortInt() + " Address: " + adrss.getHostName());
                thread_UDP.setName(this.getName() + " UDP on port: " + port.getPortInt() + " Address: " + adrss.getHostName());
                thread_TCP.start();
                thread_UDP.start();
                return;
            }

            while (true) {

                if (connType == ConnectionType.TCP) {

                    try {
                        server = new ServerSocket(port.getPortInt(), 1, adrss);
                        
                        while (true) {
                            final Socket socket;
                            socket = server.accept();

                            Runnable onConnectionThread = new Runnable() {
                                @Override
                                public void run() {
                                    onTCPConnectionReceived(socket);
                                }
                            };

                            Thread connectionProcess = new Thread(onConnectionThread);
                            this.setName(this.getName() + " TCP on port: " + port.getPortInt() + " Address: " + adrss.getHostName());
                            connectionProcess.start();

                        }
                    } catch (IOException ex) {
                        Logger.getLogger(TransactionListener.class.getName()).log(Level.SEVERE, null, ex);
                    }
                } else if (connType == ConnectionType.UDP) {

                    UDPSocket = Ports.getUDPSocket(adrss, port);
                    while (true) {
                        final DatagramPacket updPacket = new DatagramPacket(new byte[1450], 1450);

                        Runnable onConnectionThread = new Runnable() {
                            @Override
                            public void run() {
                                onUDPConnectionReceived(updPacket, UDPSocket);
                            }
                        };

                        Thread connectionProcess = new Thread(onConnectionThread);
                        this.setName(this.getName() + " UDP on port: " + port.getPortInt() + " Address: " + adrss.getHostName());
                        UDPSocket.receive(updPacket);
                        connectionProcess.start();
                    }
                }
            }

        } catch (IOException ex) {
            Logger.getLogger(TransactionListener.class.getName()).log(Level.SEVERE, null, ex);

        }
    }

    public abstract void onTCPConnectionReceived(Socket socket);

    public abstract void onUDPConnectionReceived(DatagramPacket packet, DatagramSocket UDPSocket);

    protected DatagramSocket getUDPSocket() {
        if (UDPSocket != null) {
            return UDPSocket;
        } else {
            return null;
        }
    }

    public abstract String setTransactionName();

}
