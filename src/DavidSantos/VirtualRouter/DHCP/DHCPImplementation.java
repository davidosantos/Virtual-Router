/* 
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.DHCP;

import java.io.IOException;
import java.net.UnknownHostException;

public interface DHCPImplementation {

    public abstract void onDHCPPackageReceived(DHCPPacket packet);

    public abstract void onDHCPPackageSent(DHCPPacket packet);

    public abstract void onIPacknowledged(String ip);

    public abstract String getNextAvlIP();

    public abstract String getServerIP();

    public abstract String getMaskIP();

    public abstract String getDefaultGatewayIP();

    public abstract void onUnknownHostException(UnknownHostException ex);

    public abstract void onIOException(IOException ex);

    public abstract void onAssertionError(AssertionError ex);

    public abstract void onIOException(java.lang.Exception ex);

    public abstract String getDefaultRouterIP();

    public abstract String getStaticRouteTable();

    public abstract int getTimeOffset();

    public abstract String getTimeServer();

    public abstract String[] getNameServers();

    public abstract String[] getDNSServers();

    public abstract String getDomainName();

    public abstract boolean IPAddressRequest(String ip, String mac, String hostname);

    public int getAddressLeaseTime();

    public String getDHCPServerIP();

    public int getRebindingTime();

    public int getRenewalTime();

}
