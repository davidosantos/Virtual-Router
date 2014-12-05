/*
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */
package DavidSantos.VirtualRouter.PPP.LCP;

/**
 *
 * @author root
 */
public class MagicNumber {

    private int Number;

    public MagicNumber(int Numer) {
        this.Number = Numer;
    }

    public int getNumer() {
        return Number;
    }

    public void setNumer(int Numer) {
        this.Number = Numer;
    }

    @Override
    public String toString() {
        return "0x" + Integer.toHexString(Number);
    }

    public boolean equals(MagicNumber obj) {

        return this.Number == obj.getNumer();
    }

    public byte[] toArray() {
        return new byte[]{(byte) (this.Number >> 24 & 0xFF), (byte) (this.Number >> 16 & 0xFF), (byte) (this.Number >> 8 & 0xFF), (byte) (this.Number & 0xFF)};
    }

}
