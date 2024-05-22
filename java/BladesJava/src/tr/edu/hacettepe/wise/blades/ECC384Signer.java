package tr.edu.hacettepe.wise.blades;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.web3j.crypto.Hash;


import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class ECC384Signer {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        // Generate ECC 384 key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp384r1");
        keyPairGenerator.initialize(ecSpec, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        System.out.println("Private Key: " + Hex.toHexString(privateKey.getEncoded()));
        System.out.println("Public Key: " + Hex.toHexString(publicKey.getEncoded()));

        // Example certid and messageDigest values (byte arrays)
        byte[] certid = "exampleCertId".getBytes("UTF-8");
        byte[] messageDigest = "exampleMessageDigest".getBytes("UTF-8");

        // Hash certid and messageDigest using keccak256
        byte[] hashedCertId = Hash.sha3(certid);
        byte[] hashedMessageDigest = Hash.sha3(messageDigest);

        System.out.println("Hashed CertId: " + Hex.toHexString(hashedCertId));
        System.out.println("Hashed Message Digest: " + Hex.toHexString(hashedMessageDigest));

        // Merge hashedCertId and hashedMessageDigest
        byte[] mergedHash = new byte[hashedCertId.length + hashedMessageDigest.length];
        System.arraycopy(hashedCertId, 0, mergedHash, 0, hashedCertId.length);
        System.arraycopy(hashedMessageDigest, 0, mergedHash, hashedCertId.length, hashedMessageDigest.length);

        // Hash the merged hash with keccak256
        byte[] finalHash = Hash.sha3(mergedHash);

        System.out.println("Merged and Hashed: " + Hex.toHexString(finalHash));

        Signature ecdsaSign = Signature.getInstance("SHA384withECDSA");
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(finalHash);
        byte[] signatureBytes = ecdsaSign.sign();

        // Splitting the DER-encoded signature into r and s values
        int len = signatureBytes.length / 2;
        byte[] r = new byte[len];
        byte[] s = new byte[len];
        System.arraycopy(signatureBytes, 0, r, 0, len);
        System.arraycopy(signatureBytes, len, s, 0, len);

        System.out.println("Signature R: " + bytesToHex(r));
        System.out.println("Signature S: " + bytesToHex(s));




        // For verification, we'll use the r, s, and v values in the Solidity contract
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}