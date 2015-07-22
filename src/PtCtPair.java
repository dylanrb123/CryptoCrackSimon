/**
 * A simple class to represent a plaintext - ciphertext pair, along with some utility functions
 *
 * @author Dylan Bannon <drb2857@rit.edu>
 * 4/8/2015
 */
public class PtCtPair {
    /** the plaintext */
    public final long plainText;
    /** the ciphertext */
    public final long cipherText;

    /**
     * Constructs a PtCtPair given a plaintext and a ciphertext
     * 
     * @param plainText the plaintext
     * @param cipherText the ciphertext
     */
    public PtCtPair(long plainText, long cipherText) {
        this.plainText = plainText;
        this.cipherText = cipherText;
    }

    /**
     * Gets the right (lower) half of the plaintext
     * 
     * @return the right half of the plaintext (24 bits)
     */
    public int getPlaintextRight() {
        return (int) plainText & CrackSimonUtils.MASK_24_BIT;
    }

    /**
     * Gets the left (upper) half of the plaintext
     * 
     * @return the left half of the plaintext (24 bits)
     */
    public int getPlaintextLeft() {
        return (int) (plainText >>> 24) & CrackSimonUtils.MASK_24_BIT;
    }

    /**
     * Gets the right (upper) half of the ciphertext
     * 
     * @return the right half of the ciphertext (24 bits)
     */
    public int getCiphertextRight() {
        return (int) cipherText & CrackSimonUtils.MASK_24_BIT;
    }

    /**
     * Gets the left (lower) half of the ciphertext
     * 
     * @return the left half of the ciphertext (24 bits)
     */
    public int getCiphertextLeft() {
        return (int) (cipherText >>> 24) & CrackSimonUtils.MASK_24_BIT;
    }

    @Override
    public String toString() {
        return "(pt: " + plainText + " ct: " + cipherText + ")";
    }

}
