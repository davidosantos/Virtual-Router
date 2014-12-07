/* 
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.UserInterface;

import DavidSantos.VirtualRouter.DHCP.*;
import DavidSantos.VirtualRouter.DNS.DNSImplementation;
import DavidSantos.VirtualRouter.DNS.DNSTransaction;
import DavidSantos.VirtualRouter.Gateway.GatewayTransaction;
import DavidSantos.VirtualRouter.NetInterface.Net_Interfaces;
import DavidSantos.VirtualRouter.Router;
import DavidSantos.VirtualRouter.RouterImplementation;
import DavidSantos.VirtualRouter.TCP.TCPTransaction;
import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author root
 */
public class UserInterface extends javax.swing.JFrame implements DHCPImplementation, DNSImplementation, RouterImplementation {

    private DHCPTransaction dhcpTransaction;
    private TCPTransaction tcp;
    private static DNSTransaction dns;
    private static GatewayTransaction gateway;
    Router router;

    /**
     * Creates new form UserInterface
     */
    public UserInterface() {
        initComponents();
        //try {
        //dhcpTransaction = new DHCPTransaction(this);
        //dhcpTransaction.start();

        //tcp = new TCPTransaction();
        //tcp.start();
        router = new Router(this);

        router.startRouter();

        // dns = new DNSTransaction(this, InetAddress.getByName("172.27.59.172"));
        //dns.startService();
        //gateway = new GatewayTransaction(InetAddress.getByName("172.27.59.172"), Ports.PortsNumber.Port_DNS, TransactionListener.ConnectionType.Both);
        //gateway.startService();
        // } catch (IOException ex) {
        // Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
        //  }
        try {
            Net_Interfaces ni = new Net_Interfaces();
            ni.printNames();
        } catch (SocketException ex) {
            Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        jTextArea = new javax.swing.JTextArea();
        jButton_PPPoE = new javax.swing.JButton();
        jTextField_user = new javax.swing.JTextField();
        jTextField_Password = new javax.swing.JTextField();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jTextArea.setBackground(new java.awt.Color(0, 0, 0));
        jTextArea.setColumns(20);
        jTextArea.setFont(new java.awt.Font("Dialog", 1, 18)); // NOI18N
        jTextArea.setForeground(new java.awt.Color(255, 255, 255));
        jTextArea.setRows(5);
        jScrollPane1.setViewportView(jTextArea);

        jButton_PPPoE.setText("Start PPPoE");
        jButton_PPPoE.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton_PPPoEActionPerformed(evt);
            }
        });

        jLabel1.setText("User Name");

        jLabel2.setText("Password");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 952, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addContainerGap(34, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addComponent(jLabel2)
                        .addGap(199, 199, 199)
                        .addComponent(jButton_PPPoE)
                        .addGap(80, 80, 80))))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jTextField_Password, javax.swing.GroupLayout.PREFERRED_SIZE, 152, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jTextField_user, javax.swing.GroupLayout.PREFERRED_SIZE, 152, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(233, 233, 233))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(19, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jTextField_user, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel1))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButton_PPPoE)
                    .addComponent(jTextField_Password, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel2))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 442, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButton_PPPoEActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton_PPPoEActionPerformed
        router.startPPPoEService();
    }//GEN-LAST:event_jButton_PPPoEActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(UserInterface.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(UserInterface.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(UserInterface.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(UserInterface.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new UserInterface().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton_PPPoE;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTextArea jTextArea;
    private javax.swing.JTextField jTextField_Password;
    private javax.swing.JTextField jTextField_user;
    // End of variables declaration//GEN-END:variables

    @Override
    public void onDHCPPackageReceived(DHCPPacket packet) {
        this.jTextArea.append(packet.toString());
    }

    @Override
    public void onDHCPPackageSent(DHCPPacket packet) {
        this.jTextArea.append(packet.toString());
    }

    @Override
    public String getNextAvlIP() {
        return "172.27.59.179";
    }

    @Override
    public String getServerIP() {
        return "192.168.0.104";
    }

    @Override
    public String getDefaultGatewayIP() {
        return "192.168.0.104";
    }

    @Override
    public String getMaskIP() {
        return "255.255.255.0";
    }

    @Override
    public void onUnknownHostException(UnknownHostException ex) {
        jTextArea.append(ex.getMessage());
    }

    @Override
    public void onIOException(IOException ex) {
        jTextArea.append(ex.getMessage());
    }

    @Override
    public void onAssertionError(AssertionError ex) {
        jTextArea.append(ex.getMessage());
    }

    @Override
    public void onIOException(Exception ex) {
        jTextArea.append(ex.getMessage());
    }

    @Override
    public String getDefaultRouterIP() {
        return "192.168.0.104";
    }

    @Override
    public String getStaticRouteTable() {
        return "192.168.0.104";
    }

    @Override
    public void onIPacknowledged(String ip) {
        jTextArea.append("IP acknowledged: " + ip + "\n");
    }

    @Override
    public int getTimeOffset() {
        return new Date().getTimezoneOffset();
    }

    @Override
    public String getTimeServer() {
        return null;
    }

    @Override
    public String[] getNameServers() {
        return null;
    }

    @Override
    public String[] getDNSServers() {
        String[] dns = new String[1];

        dns[0] = "172.27.59.147";

        return dns;
    }

    @Override
    public String getDomainName() {
        return null;
    }

    @Override
    public boolean IPAddressRequest(String ip, String mac, String hostname) {

        jTextArea.append("Requested ip: " + ip + " MAC: " + " Hostname: " + hostname);
        return true;
    }

    @Override
    public int getAddressLeaseTime() {
        return 7200; //two hours
    }

    @Override
    public String getDHCPServerIP() {

        return "192.168.0.104";
    }

    @Override
    public int getRebindingTime() {
        return 7200; //two hours
    }

    @Override
    public int getRenewalTime() {
        return 7200; //two hours
    }

    @Override
    public InetAddress getDNSServerAdrssToRedirect() {
        try {
            return InetAddress.getByName("8.8.4.4");
        } catch (UnknownHostException ex) {
            Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public boolean allowDNSRequest(String host, String toDomain) {
        jTextArea.append("\nDNS Allow acess of " + host + " to " + toDomain + "?, for now is true\n");
        return true;
    }

    @Override
    public void DNSOIExcetion(String error) {
        jTextArea.append("\nDNS Error: " + error + "\n");
    }

    @Override
    public InetAddress getDNSServerAdrss() {
        try {
            return InetAddress.getByName("172.27.59.172");
        } catch (UnknownHostException ex) {
            Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public boolean getDNSShowIRedirectDiniedRequests() {
        return true;
    }

    @Override
    public InetAddress getDNSDiniedRequestsShouldBeRedirectedTo() {
        try {
            return InetAddress.getByName("208.70.188.57");
        } catch (UnknownHostException ex) {
            Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public String[] getPPPoEUser() {
        return new String[]{jTextField_user.getText(), jTextField_Password.getText()};
    }
}
