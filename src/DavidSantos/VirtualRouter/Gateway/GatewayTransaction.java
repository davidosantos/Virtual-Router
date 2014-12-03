/* 
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.Gateway;

import DavidSantos.VirtualRouter.Ports.Ports;
import DavidSantos.VirtualRouter.TransactionListener;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author root
 */
public class GatewayTransaction extends TransactionListener {

    public GatewayTransaction(InetAddress adrss, Ports.PortsNumber port, ConnectionType connType) {
        super(adrss, port, connType);
    }

    public void startService() {
        super.start();
    }

    @Override
    public void onTCPConnectionReceived(Socket socket) {
        
        System.out.println("From IP: " + socket.getInetAddress() + " port: "+ socket.getPort());
        try {
            this.sleep(30*1000);
        } catch (InterruptedException ex) {
            Logger.getLogger(GatewayTransaction.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public void onUDPConnectionReceived(DatagramPacket packet, DatagramSocket UDPSocket) {
        try {
            this.sleep(30*1000);
        } catch (InterruptedException ex) {
            Logger.getLogger(GatewayTransaction.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public String setTransactionName() {
        return "Gateway";
    }

}
