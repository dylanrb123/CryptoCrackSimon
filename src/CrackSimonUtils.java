/**
 * A class containing a number of static utility functions used to crack 3 rounds of the SIMON 48/96 block cipher.
 *
 * @author Dylan Bannon <drb2857@rit.edu>
 * 4/16/2015
 */
public class CrackSimonUtils {

    /** a 24 bit mask */
    public static final int MASK_24_BIT = 0xffffff;

    /**
     * Rotates the given int by distance bits, treats it as a 24 but number (throws away upper 8 bits)
     *
     * @param number number to rotate
     * @param distance number of bits to rotate by
     * @return the rotated 24 bit number
     */
    public static int rotateLeft24Bit(int number, int distance) {
        return (number << distance | number >>> 24 - distance) & MASK_24_BIT;
    }

    /**
     * Computes a single SIMON round
     *
     * @param inputUpperHalf the upper 24 bits of the round input
     * @param inputLowerHalf the lower 24 bits of the round input
     * @param subKey the subkey (24 bits)
     * @return the result of the round. The upper 24 bits of the output are in return[1], the lower 24 bits are in return [0].
     */
    public static int[] simonRound(int inputUpperHalf, int inputLowerHalf, int subKey) {
        int[] roundOutput = new int[2];

        int andOutput = rotateLeft24Bit(inputUpperHalf, 1) & rotateLeft24Bit(inputUpperHalf, 8);
        int firstXorOutput = andOutput ^ inputLowerHalf;
        int secondXorOutput = firstXorOutput ^ rotateLeft24Bit(inputUpperHalf, 2);
        int thirdXorOutput = secondXorOutput ^ subKey;
        roundOutput[0] = inputUpperHalf;    // lower half of round output is the upper half of the input
        roundOutput[1] = thirdXorOutput;   // upper half of round output is the result of subkey XOR
        return roundOutput;
    }

    /**
     * The non-invertible function in the SIMON Feistal network
     *
     * @param input the input to the function (24 bits)
     * @return the output of the function (24 bits)
     */
    public static int simonFunction(int input) {
        return (rotateLeft24Bit(input, 8) & rotateLeft24Bit(input, 1)) ^ rotateLeft24Bit(input, 2);
    }

    /**
     * Performs the entire 3 round SIMON cipher given the three subkeys and the plaintext input
     *
     * @param plaintextUpperHalf the upper 24 bits of the plaintext
     * @param plaintextLowerHalf the lower 24 bits of the plaintext
     * @param subkey1 the round 1 subkey
     * @param subkey2 the round 2 subkey
     * @param subkey3 the round 3 subkey
     * @return the ciphertext, the upper 24 bits are stored in return[1], the lower 24 bits are stored in return[0]
     */
    public static int[] simonThreeRounds(int plaintextUpperHalf, int plaintextLowerHalf, int subkey1, int subkey2, int subkey3) {
        int[] ciphertext;
        ciphertext = simonRound(plaintextUpperHalf, plaintextLowerHalf, subkey1);
        ciphertext = simonRound(ciphertext[1], ciphertext[0], subkey2);
        ciphertext = simonRound(ciphertext[1], ciphertext[0], subkey3);
        return ciphertext;
    }

    /**
     * Converts two 24 bit numbers (stored in ints) to a single long
     *
     * @param upper the upper 24 bits of the resulting long
     * @param lower the lower 24 bits of the resulting long
     * @return the resulting long
     */
    public static long int24BitToLong(int upper, int lower) {
        long result = upper;
        result <<= 24;
        result |= (lower & MASK_24_BIT);
        return result;
    }
}
