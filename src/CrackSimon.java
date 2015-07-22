import edu.rit.util.Hex;

import java.util.*;

/**
 * Program to attack three rounds of the SIMON48/96 block cipher.
 *
 * @author Dylan Bannon <drb2857@rit.edu>
 * 4/8/2015
 */
public class CrackSimon {

    /**
     * The main method. Parses the command line args, checks for error conditions, and displays the determined subkeys.
     *
     * @param args the command line args. See usage() for specification.
     */
    public static void main(String[] args) {
        // need at least one pt ct pair
        if(args.length < 2) usage();
        // must be an even number of args
        if(args.length % 2 != 0) usage();
        // parse the command line args
        List<PtCtPair> ptCtPairs = new ArrayList<>();
        for(int i = 0; i < args.length; i += 2) {
            long pt = 0;
            long ct = 0;
            if(args[i].length() != 12 || args[i + 1].length() != 12) {
                System.err.println("Plaintext or ciphertext is incorrect length");
                System.exit(1);
            }
            try {
                pt = Hex.toLong(args[i]);
                ct = Hex.toLong(args[i + 1]);
            } catch (IllegalArgumentException e) {
                System.err.println("Plaintext or ciphertext is not a valid hex string");
                System.exit(1);
            }
            ptCtPairs.add(new PtCtPair(pt, ct));
        }
        int[] subkeys = crackSimon(ptCtPairs);
        if(subkeys != null) {
            String roundOneSubkeyString = Hex.toString(subkeys[0]).toUpperCase().substring(2);
            String roundTwoSubkeyString = Hex.toString(subkeys[1]).toUpperCase().substring(2);
            String roundThreeSubkeyString = Hex.toString(subkeys[2]).toUpperCase().substring(2);
            System.out.println(roundOneSubkeyString + "\t" + roundTwoSubkeyString + "\t" + roundThreeSubkeyString);
        }
    }

    /**
     * Performs a known plaintext attack on 3 rounds of the SIMON48/96 block cipher
     * 1) Guesses a 24 bit subkey for round 1
     * 2) Determines the other subkeys based on the plaintext, ciphertext, and the round 1 subkey guess
     * 3) Iterates through all of the remaining plaintext-ciphertext pairs and calculates the ciphertext with the
     *    guessed subkeys and the given plaintext. If the calculated ciphertext is different than the given ciphertext,
     *    then the subkey guess is incorrect. Move on to next guess.
     * 4) If all plaintext-ciphertext pairs work, then the subkey guess is correct
     * 5) If found subkey, print them all. Else, print nothing.
     *
     * @param ptCtPairs plaintext - ciphertext pairs
     * @return the subkeys used to encrypt the plaintext with 3 rounds of SIMON. NULL if no subkey found.
     */
    private static int[] crackSimon(List<PtCtPair> ptCtPairs) {
        int[] subkeys = new int[3];
        int roundOneSubkey = 0;
        int roundTwoSubkey = 0;
        int roundThreeSubkey = 0;
        boolean foundSubkey = true;

        PtCtPair ptCtPair = ptCtPairs.get(0);

        OuterLoop: for(int roundOneSubkeyGuess = 0; roundOneSubkeyGuess < 0x1000000; roundOneSubkeyGuess++) {//CrackSimonUtils.POW_2_24
            roundOneSubkey = roundOneSubkeyGuess;

            int[] roundOneOut = CrackSimonUtils.simonRound(ptCtPair.getPlaintextLeft(), ptCtPair.getPlaintextRight(), roundOneSubkey);
            roundTwoSubkey = determineRoundTwoSubkey(roundOneOut[1], ptCtPair.getPlaintextLeft(),ptCtPair.getCiphertextRight());
            roundThreeSubkey = determineRoundThreeSubkey(ptCtPair.getCiphertextRight(), roundOneOut[1], ptCtPair.getCiphertextLeft());
            for(PtCtPair ptct : ptCtPairs) {
                int[] threeRoundOut = CrackSimonUtils.simonThreeRounds(
                        ptct.getPlaintextLeft(), ptct.getPlaintextRight(), roundOneSubkey, roundTwoSubkey, roundThreeSubkey);
                long threeRoundOutLong = CrackSimonUtils.int24BitToLong(threeRoundOut[1], threeRoundOut[0]);
                if(threeRoundOutLong != ptct.cipherText) { // if the calculated ciphertext is not equal to the given, try next guess
                    foundSubkey = false;
                    continue OuterLoop;
                }
            }
            foundSubkey = true;
            break;
        }

        if(foundSubkey) {
            subkeys[0] = roundOneSubkey;
            subkeys[1] = roundTwoSubkey;
            subkeys[2] = roundThreeSubkey;
            return subkeys;
        } else {
            return null;
        }
    }

    /**
     * Calculates the round 2 subkey based on the plaintext, ciphertext, and guess for the round 1 subkey
     *
     * @param roundTwoInputLeft the left input to round 2
     * @param plaintextLeft the left plaintext
     * @param ciphertextRight the right ciphertext
     * @return the calculated round two subkey
     */
    private static int determineRoundTwoSubkey(int roundTwoInputLeft, int plaintextLeft, int ciphertextRight) {
        return plaintextLeft ^ ciphertextRight ^ CrackSimonUtils.simonFunction(roundTwoInputLeft);
    }

    /**
     * Calculates the round 3 subkey based on the ciphertext and the round 2 input
     *
     * @param ciphertextRight the right half of the ciphertext
     * @param roundTwoInputLeft the left input to round 2
     * @param ciphertextLeft the left half of the ciphertext
     * @return the calculated round 3 subkey
     */
    private static int determineRoundThreeSubkey(int ciphertextRight, int roundTwoInputLeft, int ciphertextLeft) {
        return roundTwoInputLeft ^ ciphertextLeft ^ CrackSimonUtils.simonFunction(ciphertextRight);
    }


    /**
     * Prints a usage message
     */
    private static void usage() {
        System.err.println("Usage: java CrackSimon <pt1> <ct1> [<pt2> <ct2> ...]");
        System.err.println("<pt1> is a known plaintext. It must be a 12-digit hexadecimal number (uppercase or lowercase).");
        System.err.println("<ct1> is the ciphertext corresponding to <pt1>. It must be a 12-digit hexadecimal number (uppercase or lowercase).");
        System.err.println("There must be one or more (plaintext, ciphertext) pairs.");
        System.exit(1);
    }
}
