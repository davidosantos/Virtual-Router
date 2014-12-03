/* 
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.DNS;

import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Arrays;

/**
 *
 * @author root
 */
public class DNSPacket {

    private byte Packet[];

    private boolean isInitiated = false;

    private short Query_Id;
    private boolean QuestionOrResponse;
    private int OpCode;
    private boolean AutoritiveAnswer;
    private boolean Truncated;
    private boolean RecursionDesired;
    private boolean RecursionAvailable;
    private boolean AuthenticatedData;
    private boolean CheckingDisabled;
    private int ErrorCode;
    private int NumberOfQuestions;
    private int NumberOfAnswers;
    private int NumberOfAuthorities;
    private int NumberOfadditionals;

    private Questions[] DataOfQuestions;
    private Answers[] DataOfAnswers;
    private Answers[] DataOfAuthorities;
    private Answers[] DataOfadditionals;

    public byte[] getData() {
        return Packet;
    }

    public boolean isIsInitiated() {
        return isInitiated;
    }

    public short getQuery_Id() {
        return Query_Id;
    }

    public void setQuery_Id(short Query_Id) {
        Packet[0] = (byte) (Query_Id >> 8);
        Packet[1] = (byte) (Query_Id);

        this.Query_Id = Query_Id;
    }

    public boolean isQuestionOrResponse() {
        return QuestionOrResponse;
    }

    /**
     *
     * @param QuestionResponse -- True for Question and false for Response
     */
    public void setQuestionOrResponse(boolean QuestionResponse) {

        if (QuestionResponse) {
            this.Packet[2] = unsetBit(Packet[2], 7);
        } else {
            this.Packet[2] = setBit(Packet[2], 7);
        }

        this.QuestionOrResponse = QuestionResponse;
    }

    public int getOpCode() {
        return OpCode;
    }

    public boolean isAutoritiveAnswer() {
        return AutoritiveAnswer;
    }

    public boolean isTruncated() {
        return Truncated;
    }

    public void setTruncated() {
        Packet[2] = setBit(Packet[2], 1);
    }

    public boolean isRecursionDesired() {
        return RecursionDesired;
    }

    public boolean isRecursionAvailable() {
        return RecursionAvailable;
    }

    public boolean isAuthenticatedData() {
        return AuthenticatedData;
    }

    public boolean isCheckingDisabled() {
        return CheckingDisabled;
    }

    public int getErrorCode() {
        return ErrorCode;
    }

    public void SetErrorCode(ErrorCode errocode) {

        Packet[3] = (byte) (Packet[3] | errocode.getErrorCodeNumber());

        ErrorCode = (Packet[3] & 0xF);

    }

    public int getNumberOfQuestions() {
        return NumberOfQuestions;
    }

    public int getNumberOfAnswers() {
        return NumberOfAnswers;
    }

    public int getNumberOfAuthorities() {
        return NumberOfAuthorities;
    }

    public int getNumberOfadditionals() {
        return NumberOfadditionals;
    }

    public Questions[] getDataOfQuestions() {
        return DataOfQuestions;
    }

    public Answers[] getDataOfAnswers() {
        return DataOfAnswers;
    }

    public Answers[] getDataOfAuthorities() {
        return DataOfAuthorities;
    }

    public Answers[] getDataOfadditionals() {
        return DataOfadditionals;
    }

    private boolean TrueOrFalse(int value) {

        return (value != 0);

    }

    public void initPacket(byte[] data) throws AssertionError, CustomExceptions {
        if (data.length < 6) {

            throw new AssertionError("Data less than 6 bytes");

        }

        Packet = new byte[data.length];

        for (int i = 0; i < data.length; i++) {

            Packet[i] = data[i];

            switch (i) {  //each case read two bytes total of 12 bytes
                case 0:
                    //ID
                    Query_Id = 0;
                    Query_Id = (short) ((data[i] << 8) | (data[i + 1] & 0xFF));

                    break;

                case 2:

                    QuestionOrResponse = TrueOrFalse(data[i] & 0x80);
                    OpCode = (data[i] & 0x78);
                    AutoritiveAnswer = TrueOrFalse(data[i] & 0x4);
                    Truncated = TrueOrFalse(data[i] & 0x2);
                    RecursionDesired = TrueOrFalse(data[i] & 0x1);
                    break;
                case 3:

                    RecursionAvailable = TrueOrFalse(data[i] & 0x80);

                    AuthenticatedData = TrueOrFalse(data[i] & 0x20);
                    CheckingDisabled = TrueOrFalse(data[i] & 0x10);

                    ErrorCode = (data[i] & 0xF);

                    break;
                case 4:
                    // number of questions

                    NumberOfQuestions = (short) ((data[i] << 8) | (data[i + 1] & 0xFF));

                    break;

                case 6:
                    //Total Answer RRs
                    NumberOfAnswers = (short) ((data[i] << 8) | (data[i + 1] & 0xFF));
                    break;

                case 8:
                    //Total Authority RRs
                    NumberOfAuthorities = (short) ((data[i] << 8) | (data[i + 1] & 0xFF));
                    break;
                case 10:
                    //Total Additional RRs

                    NumberOfadditionals = (short) ((data[i] << 8) | (data[i + 1] & 0xFF));

                    break;
            }
        }
        try {
            extractData();
        } catch (Exception e) {
            throw new CustomExceptions("Invalid DNS Packet or unsupported by DNSPacket.class");
        }

        isInitiated = true;

    }

    private void extractData() throws Exception {
        int totalOfQuestions = this.getNumberOfQuestions();
        int totalOfAnswers = this.getNumberOfAnswers();
        int totalOfAuthorities = this.getNumberOfAuthorities();
        int totalOfadditionals = this.getNumberOfadditionals();

        DataOfQuestions = new Questions[totalOfQuestions];
        DataOfAnswers = new Answers[totalOfAnswers];
        DataOfAuthorities = new Answers[totalOfAuthorities];
        DataOfadditionals = new Answers[totalOfadditionals];

        StringBuilder strBuilder = new StringBuilder();
        int pointer = 12; //12 length of name in the first message

        for (int i = 0; i < totalOfQuestions; i++) {
            int length = Packet[pointer++] & 0xFF;
            while (length != 0) {
                for (int j = 0; j < length; j++) {
                    strBuilder.append(new String(new byte[]{Packet[pointer++]}));
                }

                length = Packet[pointer++] & 0xFF;// next length
                if (length != 0) {
                    strBuilder.append(".");
                }

            }
            DataOfQuestions[i] = new Questions();
            DataOfQuestions[i].name = strBuilder.toString();
            DataOfQuestions[i].type = Types.getTypeName((short) ((Packet[pointer++] << 8) | (Packet[pointer++] & 0xFF)));
            DataOfQuestions[i].Class = Classes.getClassName((short) ((Packet[pointer++] << 8) | (Packet[pointer++] & 0xFF)));

        }

        for (int i = 0; i < totalOfAnswers; i++) {

            pointer++; // pointer 0xc0

            DataOfAnswers[i] = new Answers();
            DataOfAnswers[i].name = readFromAddrs(Packet[pointer++]);
            DataOfAnswers[i].type = Types.getTypeName((short) ((Packet[pointer++] << 8) | (Packet[pointer++] & 0xFF)));
            DataOfAnswers[i].Class = Classes.getClassName((short) ((Packet[pointer++] << 8) | (Packet[pointer++] & 0xFF)));
            DataOfAnswers[i].TTL = (int) ((Packet[pointer++] << 24) | (Packet[pointer++] << 16) | (Packet[pointer++] << 8) | (Packet[pointer++] & 0xFF));
            DataOfAnswers[i].RdadaLength = (short) ((Packet[pointer++] << 8) | (Packet[pointer++] & 0xFF));
            DataOfAnswers[i].Rdata = DNSPacket.this.readFromAddrs(pointer++, DataOfAnswers[i].RdadaLength);
            pointer = (pointer + DataOfAnswers[i].RdadaLength) - 1;

            //pointer++; //next message
        }

        for (int i = 0; i < totalOfAuthorities; i++) {
            pointer++; // pointer 0xc0

            DataOfAuthorities[i] = new Answers();
            DataOfAuthorities[i].name = readFromAddrs(pointer++);
            DataOfAuthorities[i].type = Types.getTypeName((short) ((Packet[pointer++] << 8) | (Packet[pointer++] & 0xFF)));
            DataOfAuthorities[i].Class = Classes.getClassName((short) ((Packet[pointer++] << 8) | (Packet[pointer++] & 0xFF)));
            DataOfAuthorities[i].TTL = (int) ((Packet[pointer++] << 24) | (Packet[pointer++] << 16) | (Packet[pointer++] << 8) | (Packet[pointer++] & 0xFF));
            DataOfAuthorities[i].RdadaLength = (short) ((Packet[pointer++] << 8) | (Packet[pointer++] & 0xFF));
            DataOfAuthorities[i].Rdata = DNSPacket.this.readFromAddrs(pointer++, DataOfAuthorities[i].RdadaLength);
            pointer += DataOfAuthorities[i].RdadaLength - 1;

            //pointer++; //next message
        }

        for (int i = 0; i < totalOfadditionals; i++) {
            pointer++; // pointer 0xc0

            DataOfadditionals[i] = new Answers();
            DataOfadditionals[i].name = readFromAddrs(pointer++);
            DataOfadditionals[i].type = Types.getTypeName((short) ((Packet[pointer++] << 8) | (Packet[pointer++] & 0xFF)));
            DataOfadditionals[i].Class = Classes.getClassName((short) ((Packet[pointer++] << 8) | (Packet[pointer++] & 0xFF)));
            DataOfadditionals[i].TTL = (int) ((Packet[pointer++] << 24) | (Packet[pointer++] << 16) | (Packet[pointer++] << 8) | (Packet[pointer++] & 0xFF));
            DataOfadditionals[i].RdadaLength = (short) ((Packet[pointer++] << 8) | (Packet[pointer++] & 0xFF));
            DataOfadditionals[i].Rdata = DNSPacket.this.readFromAddrs(pointer++, DataOfadditionals[i].RdadaLength);
            pointer += DataOfadditionals[i].RdadaLength - 1;

            //pointer++; //next message
        }

    }

    private String readFromAddrs(int Addr, int lengthData) {

        StringBuilder strBuilder = new StringBuilder();
        int Addrs = Addr;

        if (lengthData != 4) {
            int length = Packet[Addrs++] & 0xFF;
            while (length != 0) {
                for (int j = 0; j < length; j++) {

                    strBuilder.append(new String(new byte[]{Packet[Addrs++]}));

                }
                length = Packet[Addrs++] & 0xFF;// next length
                if (length == 0xc0) { //is Pointer??
                    strBuilder.append(".");
                    strBuilder.append(readFromAddrs(Packet[Addrs]));
                    return strBuilder.toString();
                }

                if (length != 0) {
                    strBuilder.append(".");
                }

            }
            return strBuilder.toString();
        } else {
            for (int i = 0; i < 4; i++) {

                strBuilder.append(Integer.toString(Packet[Addrs++] & 0xFF));

                if (i != 3) {
                    strBuilder.append(".");
                }
            }
            return strBuilder.toString();
        }
    }

    private String readFromAddrs(int Addr) {

        StringBuilder strBuilder = new StringBuilder();
        int Addrs = Addr;

        int length = Packet[Addrs++] & 0xFF;
        while (length != 0) {
            for (int j = 0; j < length; j++) {
                strBuilder.append(new String(new byte[]{Packet[Addrs++]}));

            }

            length = Packet[Addrs++] & 0xFF;// next length

            if (length == 0xc0) { //is Pointer??
                strBuilder.append(".");
                strBuilder.append(readFromAddrs(Packet[Addrs]));
                return strBuilder.toString();
            }

            if (length != 0) {
                strBuilder.append(".");
            }

        }
        return strBuilder.toString();

    }

    @Override
    public String toString() {
        StringBuilder strBuilder = new StringBuilder();

        strBuilder.append("ID: 0x").append(Integer.toHexString(this.getQuery_Id() & 0xFFFF))
                .append(" Flags: ").append(" isResponse: ").append(this.isQuestionOrResponse())
                .append(" OPCode: ").append(getOpCode())
                .append(" AutoritiveAnswer: ").append(isAutoritiveAnswer())
                .append(" Truncated: ").append(isTruncated())
                .append(" RecursionDesired: ").append(isRecursionDesired())
                .append(" RecursionAvailable: ").append(isRecursionAvailable())
                .append(" AuthenticatedData ").append(isAuthenticatedData())
                .append(" CheckingDisabled: ").append(isCheckingDisabled())
                .append(" Error Code: ").append(getErrorCode());

        strBuilder.append(" Questions: ").append(this.getNumberOfQuestions());
        strBuilder.append(" Answers: ").append(this.getNumberOfAnswers());
        strBuilder.append(" Authorities: ").append(this.getNumberOfAuthorities());
        strBuilder.append(" Addtionals: ").append(this.getNumberOfadditionals());

        strBuilder.append((DataOfQuestions == null) ? null : " DataOfQuestions: " + concatString(DataOfQuestions));
        strBuilder.append((DataOfAnswers == null) ? null : " DataOfAnswers: " + concatString(DataOfAnswers));
        strBuilder.append((DataOfAuthorities == null) ? null : " DataOfAuthorities " + concatString(DataOfAuthorities));
        strBuilder.append((DataOfadditionals == null) ? null : " DataOfadditionals " + concatString(DataOfadditionals));

        return strBuilder.toString();
    }

    private String concatString(Questions[] question) {
        StringBuilder strBuilder = new StringBuilder();

        for (Questions str : question) {
            strBuilder.append(" Name: ").append(str.name);
            strBuilder.append(" Type: ").append((str.type == null) ? "" : str.type.name());
            strBuilder.append(" Class: ").append((str.Class == null) ? "" : str.Class.name());

        }
        return strBuilder.toString();
    }

    private String concatString(Answers[] answer) {
        StringBuilder strBuilder = new StringBuilder();

        for (Answers str : answer) {
            strBuilder.append(" \nName: ").append(str.name);
            strBuilder.append(" \nType: ").append((str.type == null) ? "" : str.type.name());
            strBuilder.append(" \nClass: ").append((str.Class == null) ? "" : str.Class.name());
            strBuilder.append(" \nTTL: ").append(str.TTL);
            strBuilder.append(" \nRDAtaLength: ").append(str.RdadaLength);
            strBuilder.append(" \nRData: ").append(str.Rdata);
        }
        return strBuilder.toString();
    }

    /**
     *
     * @param value -- The Original value of the target
     * @param pos -- The position of the bit to set, starting from 0 as the
     * first bit.
     * @return -- return a value with the specific bit set (specified by pos),
     * if the bit was already set it will be kept set.
     */
    private byte setBit(byte value, int pos) {

        return (byte) ((byte) value | (1 << pos));
    }

    /**
     *
     * @param value -- The Original value of the target
     * @param pos -- The position of the bit to set, starting from 0 as the
     * first bit.
     * @return -- return a value with the specific bit unset (specified by pos),
     * if the bit was already unset it will be kept unset.
     */
    private byte unsetBit(byte value, int pos) {

        return (byte) (value & ~(1 << pos));
    }

    public class Questions {

        String name;
        Types type;
        Classes Class;
    }

    public class Answers {

        String name;
        Types type;
        Classes Class;
        int TTL;
        short RdadaLength;
        String Rdata;
    }

    protected enum Classes {

        IN(1),
        CSNET(2),
        CS(3),
        HS(4);

        private final int Class;

        private Classes(int Class) {
            this.Class = Class;
        }

        public int getClassNumber() {
            return this.Class;
        }

        public static Classes getClassName(int Number) {
            switch (Number) {
                case 1:
                    return Classes.IN;
                case 2:
                    return Classes.CSNET;
                case 3:
                    return Classes.CS;
                case 4:
                    return Classes.HS;
                default:
                    return null;
            }

        }

    }

    protected enum ErrorCode {

        NoError(0),
        FormatError(1),
        ServerFailure(2),
        NonExistDomain(3),
        QryNotImpl(4),
        QryRefused(5);

        private final int errorcode;

        private ErrorCode(int errorcode) {
            this.errorcode = errorcode;
        }

        public int getErrorCodeNumber() {
            return this.errorcode;
        }

    }

    protected enum Types {

        A(1),
        NS(2),
        CNAME(5),
        SOA(6),
        WKS(11),
        PTR(12),
        HINFO(13),
        MX(15),
        AAA(28),
        AXFR(252),
        ANY(255);

        private final int type;

        private Types(int type) {
            this.type = type;

        }

        public int getTypeNumber() {
            return type;
        }

        public static Types getTypeName(int Number) {
            switch (Number) {
                case 1:
                    return Types.A;
                case 2:
                    return Types.NS;
                case 5:
                    return Types.CNAME;
                case 6:
                    return Types.SOA;
                case 11:
                    return Types.WKS;
                case 12:
                    return Types.PTR;
                case 13:
                    return Types.HINFO;
                case 15:
                    return Types.MX;
                case 28:
                    return Types.AAA;
                case 252:
                    return Types.AXFR;
                case 255:
                    return Types.ANY;
                default:
                    return null;
            }

        }
    }

    protected byte[] createNewPacketAsnwer(byte[] data, InetAddress addrsTo) throws AssertionError, CustomExceptions, IOException {
        ByteArrayOutputStream retPacket = new ByteArrayOutputStream();
        this.initPacket(data);
        this.setQuestionOrResponse(false); //response
        this.Packet[7] = 1; // one answer
        retPacket.write(this.Packet);
        int totalOfAnswers = 1;

        DataOfAnswers = new Answers[totalOfAnswers];

        for (int i = 0; i < totalOfAnswers; i++) {

            retPacket.write((byte) 0xc0); //= (byte) 0xc0; // do the pointer
            retPacket.write((byte) 0xc); // do the pointer

            DataOfAnswers[i] = new Answers();
            DataOfAnswers[i].name = readFromAddrs(0xc); // read from pointer

            retPacket.write(0);

            retPacket.write((byte) Types.A.getTypeNumber());
            //DataOfAnswers[i].type = Types.getTypeName((short) ((Packet[pointer++] << 8) | (Packet[pointer++] & 0xFF)));
            retPacket.write(0);
            retPacket.write((byte) Classes.IN.getClassNumber());
            //DataOfAnswers[i].Class = Classes.getClassName((short) ((Packet[pointer++] << 8) | (Packet[pointer++] & 0xFF)));
            retPacket.write(0);
            retPacket.write(0);
            retPacket.write(0);
            retPacket.write((byte) 78);
            //DataOfAnswers[i].TTL = (int) ((Packet[pointer++] << 24) | (Packet[pointer++] << 16) | (Packet[pointer++] << 8) | (Packet[pointer++] & 0xFF));
            retPacket.write(0);
            retPacket.write((byte) 4);
            //DataOfAnswers[i].RdadaLength = (short) ((Packet[pointer++] << 8) | (Packet[pointer++] & 0xFF));

            for (byte bt : addrsTo.getAddress()) {
                retPacket.write(bt);
            }
           // DataOfAnswers[i].Rdata = DNSPacket.this.readFromAddrs(pointer++, 4);

        }
       
        return retPacket.toByteArray();

    }

}
