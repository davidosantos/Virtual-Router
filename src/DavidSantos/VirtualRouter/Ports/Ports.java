/* 
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.Ports;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;

/**
 *
 * @author dsantos4
 */
public final class Ports {

    public enum PortsNumber {

        Port_DNS(53),
        Port_DHCP_Receive(67),
        Port_DHCP_Reply(68),
        Port_WWW(80);

        private final int port;

        private PortsNumber(int port) {
            this.port = port;

        }

        public int getPortInt() {
            return port;
        }

    }

    public enum Timeout {

        OneMilli(1),
        OneSec(1000),
        TwoSes(2 * 1000),
        ThreeSecs(3 * 1000),
        FourSecs(4 * 1000),
        FiveSecs(5 * 1000),
        TenSecs(10 * 1000),
        Permanently(0);

        private final int timeout;

        private Timeout(int time) {
            this.timeout = time;

        }

        public int getTimeout() {
            return timeout;
        }

    }

    public synchronized static void sendDHCPData(DatagramPacket packet, PortsNumber localport, InetAddress addrs, Ports.PortsNumber remoteport) throws SocketException, IOException {
        DatagramPacket Datapacket = packet;
        Datapacket.setLength(packet.getLength());
        try (DatagramSocket socket = new DatagramSocket(localport.getPortInt())) {
            socket.connect(addrs, remoteport.getPortInt());
            socket.send(Datapacket);
            socket.close();
        }
    }

    public synchronized static DatagramPacket receiveDHCPData(Timeout timeout, PortsNumber port) throws SocketException, IOException, SocketTimeoutException {
        DatagramPacket dataPacket = new DatagramPacket(new byte[1500], 1500);

        try (DatagramSocket socket = new DatagramSocket(port.getPortInt())) {;
            socket.setSoTimeout(timeout.getTimeout());
            socket.receive(dataPacket);
            dataPacket.setData(Shrink.getShrikedData(dataPacket.getData()));
            socket.close();
        } catch (SocketTimeoutException ex) {
            throw ex;
        }

        return dataPacket;
    }

    public static DatagramPacket receiveUDPData(Timeout timeout, PortsNumber port) throws SocketException, IOException, SocketTimeoutException {
        DatagramPacket dataPacket = new DatagramPacket(new byte[1500], 1500);

        try (DatagramSocket socket = new DatagramSocket(port.getPortInt())) {;
            socket.setSoTimeout(timeout.getTimeout());
            socket.receive(dataPacket);
            dataPacket.setData(Shrink.getShrikedData(dataPacket.getData()));
            socket.close();
        } catch (SocketTimeoutException ex) {
            throw ex;
        }

        return dataPacket;
    }

    public static void sendUDPData(InetAddress localAddress, PortsNumber port, DatagramPacket data) throws SocketException, IOException, SocketTimeoutException {

        try (DatagramSocket socket = new DatagramSocket(port.getPortInt(), localAddress)) {
            socket.connect(data.getAddress(), data.getPort());
            socket.send(data);
            socket.close();
        } catch (SocketTimeoutException ex) {
            throw ex;
        }
    }

    public static DatagramPacket sendAndReceiveUDPData(InetAddress localAddress, Timeout timeout, DatagramPacket data) throws SocketException, IOException, SocketTimeoutException {
        DatagramPacket receivedData;
        try (DatagramSocket socket = new DatagramSocket(findFreeTCPPort(), localAddress)) {
            receivedData = new DatagramPacket(new byte[1500], 1500);
            socket.setSoTimeout(timeout.getTimeout());
            socket.connect(data.getAddress(), data.getPort());
            socket.send(data);
            socket.receive(receivedData);
            receivedData.setData(Shrink.getShrikedData(receivedData.getData()));
            socket.close();
            return receivedData;
        } catch (SocketTimeoutException ex) {

            throw ex;
        }
    }

    public static DatagramPacket receiveUDPData(Timeout timeout, InetAddress adrss, PortsNumber port) throws SocketException, IOException, SocketTimeoutException {
        DatagramPacket dataPacket = new DatagramPacket(new byte[1500], 1500);

        try (DatagramSocket socket = new DatagramSocket(port.getPortInt(), adrss)) {;
            socket.setSoTimeout(timeout.getTimeout());
            socket.receive(dataPacket);
            dataPacket.setData(Shrink.getShrikedData(dataPacket.getData()));
            socket.close();
        } catch (SocketException | SocketTimeoutException ex) {
            throw ex;
        }

        return dataPacket;
    }

    public static byte[] receiveTCPData(byte[] data, Timeout timeout,InetAddress localAddrs ,InetAddress adrss, PortsNumber port) throws SocketException, IOException, SocketTimeoutException {

        ByteArrayOutputStream baos;
        try (Socket dataSocket = new Socket(adrss, port.getPortInt(),localAddrs, findFreeTCPPort())) {
            dataSocket.setSoTimeout(timeout.getTimeout());
            dataSocket.getOutputStream().write(data);
            InputStream input = dataSocket.getInputStream();
            baos = new ByteArrayOutputStream();
            byte buffer[] = new byte[dataSocket.getReceiveBufferSize()];
            for (int s; (s = input.read(buffer)) != -1;) {
                baos.write(buffer, 0, s);
            }
        }

        return baos.toByteArray();

    }

    public static DatagramSocket getUDPSocket(InetAddress adrss, PortsNumber port) throws SocketException, IOException, SocketTimeoutException {

        DatagramSocket socket = new DatagramSocket(port.getPortInt(), adrss);
        return socket;

    }

    public static int findFreeTCPPort()
            throws IOException {
        int port;
        try (ServerSocket server = new ServerSocket(0)) {
            port = server.getLocalPort();
            server.close();
        }
        return port;
    }

    public static class Shrink {

        private static byte[] data;
        private static int shirinkedToAddrs;

        private static int getShrinkAddrs(byte[] data) {
            
            int Addrs=data.length;
            
            for(int i = data.length-1; data[i] == 0 ;i--){
                Addrs =i;
                    
            }
           return Addrs;
        }

        public static byte[] getShrikedData(byte[] dataToShrink) {
            shirinkedToAddrs = getShrinkAddrs(dataToShrink);
            Shrink.data = dataToShrink;

            byte[] shrinkedData = new byte[shirinkedToAddrs];
            System.arraycopy(data, 0, shrinkedData, 0, shirinkedToAddrs);
            return shrinkedData;
        }
    }
}
