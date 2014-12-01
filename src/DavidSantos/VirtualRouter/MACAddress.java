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
public class MACAddress {
    byte[] mac = new byte[6];

    public MACAddress(byte[] mac) throws CustomExceptions {
        if(mac.length != 6) throw new CustomExceptions("invalid MAC Addres, Length: " + mac.length);
        System.arraycopy(mac, 0, this.mac, 0, 6);
            
    }
    public MACAddress(String mac) throws CustomExceptions {
    }

    public byte[] getMac() {
        return mac;
    }

    @Override
    public String toString() {
        
        return String.format("%02X:%02X:%02X:%02X:%02X:%02X",mac[0],mac[1] ,mac[2] ,mac[3] ,mac[4], mac[5]);
    }
   
}
