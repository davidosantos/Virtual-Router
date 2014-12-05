/* 
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter;

import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;
import java.util.Arrays;

/**
 *
 * @author root
 */
public class MACAddress {

    byte[] mac = new byte[6];

    public MACAddress(byte[] mac) throws CustomExceptions {
        if (mac.length != 6) {
            throw new CustomExceptions("invalid MAC Addres, Length: " + mac.length);
        }
        System.arraycopy(mac, 0, this.mac, 0, 6);

    }

    public MACAddress(String mac) throws CustomExceptions {
    }

    public byte[] getMac() {
        return mac;
    }

    @Override
    public String toString() {

        return String.format("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    
    public boolean equals(MACAddress obj) {
        
        return Arrays.equals(this.mac, obj.mac);
    }

}
