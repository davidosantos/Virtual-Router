/* 
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.NetInterface;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author dsantos4
 */
public class Net_Interfaces {

    Enumeration<NetworkInterface> NetworkInterfaces;

    public Net_Interfaces() throws SocketException {
        NetworkInterfaces = NetworkInterface.getNetworkInterfaces();
    }

    public void printNames() throws SocketException {
        for (NetworkInterface nets : Collections.list(NetworkInterfaces)) {
            displayInterfaceInformation(nets);
        }

    }

    void displayInterfaceInformation(NetworkInterface netint) throws SocketException {
        System.out.printf("Display name: %s\n", netint.getDisplayName());
        System.out.printf("Name: %s\n", netint.getName());
        Enumeration<InetAddress> inetAddresses = netint.getInetAddresses();
        for (InetAddress inetAddress : Collections.list(inetAddresses)) {
            System.out.printf("InetAddress: %s\n", inetAddress);
        }
        System.out.printf("\n");

    }

    public static NetworkInterface getDHCPInterface() {

        try {

            return NetworkInterface.getByName("eth0");
        } catch (SocketException ex) {
            Logger.getLogger(Net_Interfaces.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
}
