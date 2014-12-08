/*
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.PPP.IPCP;

import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;
import java.net.InetAddress;

/**
 *
 * @author root
 */
public enum IPCPOptions {

    IPAddresses((byte) 0x01), //(deprecated)	RFC 1332
    IPCompressionProtocol((byte) 0x02),//	RFC 1332, RFC 3241, RFC 3544
    IPAddress((byte) 0x03), //RFC 1332
    MobileIPv4((byte) 0x04), //RFC 2290
    PrimaryDNSServerAddress((byte) 0x81), //RFC 1877
    PrimaryNBNSServerAddress((byte) 0x82), //RFC 1877
    SecondaryDNSServerAddress((byte) 0x83), //RFC 1877
    SecondaryNBNSServerAddress((byte) 0x84);//	RFC 1877

    private final byte option;
    
    private byte length;
    private InetAddress ip;

    private IPCPOptions(byte option) {
        this.option = option;
    }

    public static IPCPOptions getOptionName(byte number) throws CustomExceptions {
        switch (number) {

            case 0x01:
                return IPCPOptions.IPAddresses;
            case 0x02:
                return IPCPOptions.IPCompressionProtocol;
            case 0x03:
                return IPCPOptions.IPAddress;
            case 0x04:
                return IPCPOptions.MobileIPv4;
            case (byte) (0x81 & 0xFF):
                return IPCPOptions.PrimaryDNSServerAddress;
            case (byte) (0x82 & 0xFF):
                return IPCPOptions.PrimaryNBNSServerAddress;
            case (byte) (0x83 & 0xFF):
                return IPCPOptions.SecondaryDNSServerAddress;
            case (byte) (0x84 & 0xFF):
                return IPCPOptions.SecondaryNBNSServerAddress;

            default:
                throw new CustomExceptions("IPCP Options: Unknown option: " + Integer.toHexString(number & 0xff));
        }
    }

    public InetAddress getIP() {
        return ip;
    }

    public void setIP(InetAddress data) {
        this.ip = data;
        this.length = (byte) (data.getAddress().length+2);
    }

    public byte getOption() {
        return option;
    }

    public byte getLength() {
        return length;
    }

    public void setLength(byte length) {
        this.length = length;
    }
    

}
