/* 
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter;

import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;

/**
 *
 * @author root
 */
public interface RouterInterface {

    public void sendWanEthernetBroadcast(EthernetTypes type, byte[] data) throws CustomExceptions;

    public void sendWanData(EthernetTypes type, MACAddress to, byte[] data) throws CustomExceptions;

    public void startPPPoEService();
    
    public String[] getPPPoEUser();
}
