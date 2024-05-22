package tr.edu.hacettepe.wise.blades;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.web3j.crypto.Hash;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;

public class DocumentHasher {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: java DocumentHasher <documentPath> <ipfsHash>");
            return;
        }

        String documentPath = args[0];
        String ipfsHash = args[1];

        try {
            // Read the document content
            byte[] documentContent = Files.readAllBytes(Paths.get(documentPath));

            // Hash the document content using keccak256
            byte[] documentHash = Hash.sha3(documentContent);

            // Convert the IPFS hash from base58 to hex
            String ipfsHashHex = ipfsToHex(ipfsHash);

            // Compare the hashes
            if (Numeric.toHexString(documentHash).equals(ipfsHashHex)) {
                System.out.println("The document content matches the IPFS hash.");
            } else {
                System.out.println("The document content does not match the IPFS hash.");
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static String ipfsToHex(String ipfsHash) {
        // Decode the base58 IPFS hash to get the original multihash
        byte[] decodedHash = Base58.decode(ipfsHash);

        // Remove the first two bytes (the multihash prefix)
        byte[] hashBytes = new byte[decodedHash.length - 2];
        System.arraycopy(decodedHash, 2, hashBytes, 0, hashBytes.length);

        // Convert the hash to hex format
        return Numeric.toHexString(hashBytes);
    }
}

// Base58 encoding/decoding class (simplified for this example)
class Base58 {
    private static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final int BASE = ALPHABET.length();
    private static final int[] INDEXES = new int[128];

    static {
        for (int i = 0; i < INDEXES.length; i++) {
            INDEXES[i] = -1;
        }
        for (int i = 0; i < ALPHABET.length(); i++) {
            INDEXES[ALPHABET.charAt(i)] = i;
        }
    }

    public static byte[] decode(String input) {
        if (input.length() == 0) {
            return new byte[0];
        }

        byte[] input58 = new byte[input.length()];
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            int digit = -1;
            if (c >= 0 && c < 128) {
                digit = INDEXES[c];
            }
            if (digit < 0) {
                throw new IllegalArgumentException("Invalid character found: " + c);
            }
            input58[i] = (byte) digit;
        }

        int zeroCount = 0;
        while (zeroCount < input58.length && input58[zeroCount] == 0) {
            zeroCount++;
        }

        byte[] decoded = new byte[input.length()];
        int decodedLength = 0;

        for (int i = zeroCount; i < input58.length; i++) {
            int carry = input58[i] & 0xFF;
            int j = decoded.length;
            while (carry != 0 || j > decodedLength) {
                carry += BASE * (decoded[--j] & 0xFF);
                decoded[j] = (byte) (carry % 256);
                carry /= 256;
            }
            decodedLength = decoded.length - j;
        }

        int outputLength = decodedLength + zeroCount;
        byte[] output = new byte[outputLength];
        System.arraycopy(decoded, decoded.length - decodedLength, output, zeroCount, decodedLength);
        return output;
    }
}