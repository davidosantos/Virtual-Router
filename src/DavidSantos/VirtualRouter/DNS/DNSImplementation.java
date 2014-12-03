/* 
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.DNS;

import java.net.InetAddress;

/**
 *
 * @author root
 */
public interface DNSImplementation {

    public InetAddress getDNSServerAdrssToRedirect();

    public InetAddress getDNSServerAdrss();

    public boolean allowDNSRequest(String host, String toDomain);

    public boolean getDNSShowIRedirectDiniedRequests();

    public InetAddress getDNSDiniedRequestsShouldBeRedirectedTo();

    public void DNSOIExcetion(String error);

}
