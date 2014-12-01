/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package DavidSantos.VirtualRouter;

import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;

/**
 *
 * @author root
 */
public interface RouterInterface {
    
    public void sendWanEthernetBroadcast(EthernetTypes type, byte[] data) throws CustomExceptions;
    
    public void sendWanData(EthernetTypes type, MACAddress to , byte[] data) throws CustomExceptions;
    
    public void startPPPoEService();
}
