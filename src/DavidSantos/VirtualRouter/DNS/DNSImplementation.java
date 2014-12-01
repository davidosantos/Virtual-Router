/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
    
    public boolean allowDNSRequest(String host ,String toDomain);
    
    public boolean getDNSShowIRedirectDiniedRequests();
    
    public InetAddress getDNSDiniedRequestsShouldBeRedirectedTo();
    
    public void DNSOIExcetion(String error);
    
}
