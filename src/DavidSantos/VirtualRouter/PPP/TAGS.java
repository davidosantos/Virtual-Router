/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package DavidSantos.VirtualRouter.PPP;

import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;

/**
 *
 * @author root
 */
public enum TAGS {
    
//    1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |          TAG_TYPE             |        TAG_LENGTH             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |          TAG_VALUE ...                                        ~
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    
    

    /**
     * This TAG indicates that there are no further TAGs in the list. The
     * TAG_LENGTH of this TAG MUST always be zero. Use of this TAG is not
     * required, but remains for backwards compatibility.
     */
    End_Of_List((short) 0x0000),
    /**
     * This TAG indicates that a service name follows. The TAG_VALUE is // an
     * UTF-8 string that is NOT NULL terminated. When the TAG_LENGTH // is zero
     * this TAG is used to indicate that any service is // acceptable. Examples
     * of the use of the Service-Name TAG are to // indicate an ISP name or a
     * class or quality of service.
     */
    Service_Name((short) 0x0101),
    /**
     * This TAG indicates that a string follows which uniquely identifies //
     * this particular Access Concentrator unit from all others. It may // be a
     * combination of trademark, model, and serial id information, // or simply
     * an UTF-8 rendition of the MAC address of the box. It is // not NULL
     * terminated.
     */
    AC_Name((short) 0x0102),
    /**
     * This TAG is used by a Host to uniquely associate an Access //
     * Concentrator response (PADO or PADS) to a particular Host request //
     * (PADI or PADR). The TAG_VALUE is binary data of any value and // length
     * that the Host chooses. It is not interpreted by the Access //
     * Concentrator. The Host MAY include a Host-Uniq TAG in a PADI or // PADR.
     * If the Access Concentrator receives this TAG, it MUST // include the TAG
     * unmodified in the associated PADO or PADS // response.
     */
    Host_Uniq(
            (short) 0x0103),
    /**
     * This TAG is used by the Access Concentrator to aid in protecting //
     * against denial of service attacks (see the Security Considerations //
     * section for an explanation of how this works). The Access // Concentrator
     * MAY include this TAG in a PADO packet. If a Host // receives this TAG, it
     * MUST return the TAG unmodified in the // following PADR. The TAG_VALUE is
     * binary data of any value and // length and is not interpreted by the
     * Host.
     */
    AC_Cookie((short) 0x0104);

    private final short type;
    
    private short length;
    private byte[] data;
    

    public short getType() {
        return type;
    }

    public static TAGS getTypeName(int Number) throws CustomExceptions {
        switch (Number) {
            case 0x0000:
                return TAGS.End_Of_List;
            case 0x0101:
                return TAGS.Service_Name;
            case 0x0102:
                return TAGS.AC_Name;
            case 0x0103:
                return TAGS.Host_Uniq;
            case 0x0104:
                return TAGS.AC_Cookie;

            default:
                throw new CustomExceptions("PPP Tag Unknown: 0x" + Integer.toHexString(Number));
        }

    }

    private TAGS(short type) {
        this.type = type;

    }

    public short getLength() {
        return length;
    }

    public void setLength(short length) {
        this.length = length;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
        this.length = (short) data.length;
    }

}
