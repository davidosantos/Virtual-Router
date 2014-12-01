/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package DavidSantos.VirtualRouter.PPP;

import DavidSantos.VirtualRouter.EthernetTypes;
import DavidSantos.VirtualRouter.Exceptions.CustomExceptions;
import DavidSantos.VirtualRouter.MACAddress;
import DavidSantos.VirtualRouter.RouterInterface;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author root
 */
public class PPPTransaction {

    private WaitingFor waitingFor = WaitingFor.none;
    Random random = new Random();
    TAGS ACName;
    TAGS ACCookie;
    TAGS hostUniq;
    byte[] dataTagHostUniq = new byte[4]; //new byte[]{(byte) 0x94, (byte) 0x98, (byte) 0x00, (byte) 0x00,};
    MACAddress from;

    short SessionStabilished; /// must test session before sending data.

    RouterInterface routerInterface;

    public PPPTransaction(RouterInterface routerInterface) {
        this.routerInterface = routerInterface;
        this.random.nextBytes(dataTagHostUniq);
    }

    void Send(PPPoEDiscovery discovery) throws CustomExceptions {

    }

    public void onReceive_Session_St(PPPoEDiscovery session) {

    }

    public void onReceive_Discovery_St(PPPoEDiscovery discovery) throws CustomExceptions {
        System.out.println("New packet;");

        if (waitingFor == WaitingFor.Offer) {
            if (discovery.getCode() == PPPCodes.PADO) {

                for (TAGS tag : discovery.getPayload()) {
                    if (tag == TAGS.Host_Uniq) {
                        if (Arrays.equals(tag.getData(), dataTagHostUniq)) {
                            this.hostUniq = tag;
                        } else {
                            throw new CustomExceptions("Error when treating PADO the field HostUniq of the packet received is differs from the sent, sent was: "
                                    + Arrays.toString(dataTagHostUniq) + " Recieved is: " + Arrays.toString(tag.getData()));
                        }
                    }
                }

                if (discovery.getCode().getFrom() == null) {
                    throw new CustomExceptions("Error the field 'From' of the packet received is null");
                } else {
                    this.from = discovery.getCode().getFrom();
                }

                for (TAGS tag : discovery.getPayload()) {
                    if (tag == TAGS.AC_Name) {
                        this.ACName = tag;
                    }
                }

                for (TAGS tag : discovery.getPayload()) {
                    if (tag == TAGS.AC_Cookie) {
                        this.ACCookie = tag;
                    }
                }

                short session = 0;

                TAGS service_name = TAGS.Service_Name;
                service_name.setData("David".getBytes());

                TAGS[] tags = new TAGS[3];
                tags[0] = service_name;
                tags[1] = hostUniq;
                tags[2] = ACCookie;

                PPPoEDiscovery discoveryRequest = new PPPoEDiscovery(PPPCodes.PADR, session, tags);

                routerInterface.sendWanData(EthernetTypes.PPP_Discovery_St, this.from, discoveryRequest.getBytes());
                this.waitingFor = WaitingFor.Ack;

            } else {
                throw new CustomExceptions("I was waitiong for a PADO Packet, But I recieved: " + discovery.getCode().name() + " From " + discovery.getCode().getFrom().toString());
            }
        } else if (waitingFor == WaitingFor.Ack) {
            if (discovery.getCode() == PPPCodes.PADS) {

                for (TAGS tag : discovery.getPayload()) {
                    if (tag == TAGS.Host_Uniq) {
                        if (Arrays.equals(tag.getData(), dataTagHostUniq)) {
                            this.hostUniq = tag;
                        } else {
                            throw new CustomExceptions("Error when treating PADS the field HostUniq of the packet received is differs from the sent, sent was: "
                                    + Arrays.toString(dataTagHostUniq) + " Recieved is: " + Arrays.toString(tag.getData()));
                        }
                    }
                }

                if (discovery.getCode().getFrom() == null) {
                    throw new CustomExceptions("Error the field 'From' of the packet received is null");
                } else {
                    this.from = discovery.getCode().getFrom();
                }

                for (TAGS tag : discovery.getPayload()) {
                    if (tag == TAGS.AC_Cookie) {
                        if (Arrays.equals(this.ACCookie.getData(), tag.getData())) {
                            //Ok Cookie Match
                        } else {
                            throw new CustomExceptions("Invalid cookie recieved: " + Arrays.toString(tag.getData()) + " From " + discovery.getCode().getFrom().toString()
                                    + " The right is: " + Arrays.toString(this.ACCookie.getData()));
                        }
                    }
                }
                if (discovery.getSession_Id() == 0) {
                    throw new CustomExceptions("There was a error, session returned is 0: " + discovery.getCode().name() + " From " + discovery.getCode().getFrom().toString());
                } else {
                    this.SessionStabilished = discovery.getSession_Id();
                    System.out.println("Session is : " + this.SessionStabilished);
                    waitingFor = WaitingFor.Everything;
                }

            } else {
                throw new CustomExceptions("I was waitiong for a PADS Packet, But I recieved: " + discovery.getCode().name() + " From " + discovery.getCode().getFrom().toString());
            }
        } else if (waitingFor == WaitingFor.Everything) {
            if (discovery.getCode() == PPPCodes.PADT) {
                if (Arrays.equals(discovery.getCode().getFrom().getMac(), this.from.getMac())) {
                    this.SessionStabilished = 0;
                    ACName = null;
                    ACCookie = null;
                    hostUniq = null;
                    from = null;
                }
            }
        }
    }

    public void start() {
        TAGS[] tags = new TAGS[2];
        TAGS hostunique = TAGS.Host_Uniq;
        hostunique.setData(dataTagHostUniq);

        TAGS service_name = TAGS.Service_Name;
        service_name.setData("David".getBytes());

        tags[0] = service_name;
        tags[1] = hostunique;

        short session = 0;

        PPPoEDiscovery discoveryReply = new PPPoEDiscovery(PPPCodes.PADI, session, tags);

        try {
            routerInterface.sendWanEthernetBroadcast(EthernetTypes.PPP_Discovery_St, discoveryReply.getBytes());
            this.waitingFor = WaitingFor.Offer;
        } catch (CustomExceptions ex) {
            Logger.getLogger(PPPTransaction.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    private enum WaitingFor {

        Offer,
        Ack,
        Everything,
        none;
    }

}
