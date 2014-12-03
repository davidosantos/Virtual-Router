/* 
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.PPP.LCP;

import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;

/**
 *
 * @author root
 */
public enum LCPCodes {

    Configure_Rq((byte) 0x01),
    Configure_Ack((byte) 0x02),
    Configure_Nak((byte) 0x03),
    /**
     * Configure-Reject
     *
     * Description
     *
     * If some Configuration Options received in a Configure-Request are not
     * recognizable or are not acceptable for negotiation (as configured by a
     * network administrator), then the implementation MUST transmit a
     * Configure-Reject. The Options field is filled with only the unacceptable
     * Configuration Options from the Configure-Request. All recognizable and
     * negotiable Configuration Options are filtered out of the
     * Configure-Reject, but otherwise the Configuration Options MUST NOT be
     * reordered or modified in any way.
     *
     * On reception of a Configure-Reject, the Identifier field MUST match that
     * of the last transmitted Configure-Request. Additionally, the
     * Configuration Options in a Configure-Reject MUST
     *
     *
     *
     * Simpson [Page 31]
     *
     * RFC 1661 Point-to-Point Protocol July 1994
     *
     *
     * be a proper subset of those in the last transmitted Configure- Request.
     * Invalid packets are silently discarded.
     *
     * Reception of a valid Configure-Reject indicates that when a new
     * Configure-Request is sent, it MUST NOT include any of the Configuration
     * Options listed in the Configure-Reject.
     *
     * A summary of the Configure-Reject packet format is shown below. The
     * fields are transmitted from left to right.
     *
     * 0 1 2 3
     * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | Code
     * | Identifier | Length |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
     * Options ... +-+-+-+-+
     *
     *
     * Code
     *
     * 4 for Configure-Reject.
     *
     * Identifier
     *
     * The Identifier field is a copy of the Identifier field of the
     * Configure-Request which caused this Configure-Reject.
     *
     * Options
     *
     * The Options field is variable in length, and contains the list of zero or
     * more Configuration Options that the sender is rejecting. All
     * Configuration Options are always rejected simultaneously.
     *
     */
    Configure_Rej((byte) 0x04),
    Terminate_Rq((byte) 0x05),
    Terminate_Ack((byte) 0x06),
    Code_Rej((byte) 0x07),
    Protocol_Rej((byte) 0x08),
    Echo_Rq((byte) 0x09),
    Echo_Reply((byte) 0x10),
    Discard_Rq((byte) 0x11),
    LinkQuality_Rpt((byte) 0x12);

    private final byte code;

    public byte getCode() {
        return code;
    }

    private LCPCodes(byte code) {
        this.code = code;
    }

    public static LCPCodes getCode(int number) throws CustomExceptions {
        switch (number) {
            case 0x01:
                return LCPCodes.Configure_Rq;

            case 0x02:

                return LCPCodes.Configure_Ack;
            case 0x03:

                return LCPCodes.Configure_Nak;
            case 0x04:

                return LCPCodes.Configure_Rej;
            case 0x05:

                return LCPCodes.Terminate_Rq;
            case 0x06:

                return LCPCodes.Terminate_Ack;
            case 0x07:

                return LCPCodes.Code_Rej;
            case 0x08:

                return LCPCodes.Protocol_Rej;
            case 0x09:

                return LCPCodes.Echo_Rq;
            case 0x10:

                return LCPCodes.Echo_Reply;
            case 0x11:

                return LCPCodes.Discard_Rq;
            case 0x12:
                return LCPCodes.LinkQuality_Rpt;

            default:
                throw new CustomExceptions("LCP Code Unknown 0x" + Integer.toHexString(number));
        }
    }

}
