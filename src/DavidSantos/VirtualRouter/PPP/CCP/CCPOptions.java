/*
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.PPP.CCP;

import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;

/**
 *
 * @author root
 */
public enum CCPOptions {

    OUI((byte) 0x00),
    PredicatorType1((byte) 0x01),
    PredicatorType2((byte) 0x02),
    PuddleJumper((byte) 0x03),
    HewlettPackartPPC((byte) 0x10),
    StacElectronicsLZS((byte) 0x11),
    MicrosoftCCP((byte) 0x12),
    GandalfFZA((byte) 0x13),
    V42biscompression((byte) 0x14),
    BSDLZWCompress((byte) 0x15);

    private final byte option;

    private byte length;
    private byte[] data;

    private CCPOptions(byte option) {
        this.option = option;
    }

    public static CCPOptions getOptionName(byte number) throws CustomExceptions {
        switch (number) {

            case 0x00:
                return CCPOptions.OUI;
            case 0x01:
                return CCPOptions.PredicatorType1;
            case 0x02:
                return CCPOptions.PredicatorType2;
            case 0x03:
                return CCPOptions.PuddleJumper;
            case 0x10:
                return CCPOptions.HewlettPackartPPC;
            case 0x11:
                return CCPOptions.StacElectronicsLZS;
            case 0x12:
                return CCPOptions.MicrosoftCCP;
            case 0x13:
                return CCPOptions.GandalfFZA;
            case 0x14:
                return CCPOptions.V42biscompression;
            case 0x15:
                return CCPOptions.BSDLZWCompress;

            default:
                throw new CustomExceptions("CCP Options: Unknown option: " + Integer.toHexString(number & 0xff));
        }
    }

    public byte getLength() {
        return length;
    }

    public void setLength(byte length) {
        this.length = length;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public byte getOption() {
        return option;
    }
    
    

}
