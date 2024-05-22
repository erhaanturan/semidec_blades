// SPDX-License-Identifier: Hacettepe Wise Lab
pragma solidity ^0.8.0;


import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

interface SemiDecPKI {
    function verifyCertificate(uint64 _certificateId) external view returns (bool);
}

contract BlAdES {
    using ECDSA for bytes32;
    
    function validateECCSignature(
        bytes32 messageHash,
        bytes memory signature,
        bytes32 publicKey
    ) internal pure returns (address) {
          // Recover the address that signed the messageHash with the provided signature
        address recoveredSigner = messageHash.toEthSignedMessageHash().recover(signature);

        // Check if the recovered address matches the expected signer address
        return (recoveredSigner == expectedSigner);
        
        // Verify that the recovered address matches the provided public key
        require(signer == address(uint256(publicKey)), "Invalid signature");
        
        return signer;
    }
    
    SemiDecPKI semiDecPKI; // Reference to the SemiDecPKI contract
    
    constructor(address _semiDecPKIAddress) {
        semiDecPKI = SemiDecPKI(_semiDecPKIAddress);
    }

    struct Signature {
        uint signatureId;
        uint certificateId;
        string messageDigest;
        bool isContentConfidential;
        bytes32 data; // IPFS address of content
        uint8 signaturePolicy; // 0 = private key, 1 = transaction key
        bytes32 cryptographicSignature; // ECC-384 signature
        bytes20 signerAddress; // Ethereum address of the signer
        uint parentSignatureId; // for serial signatures; parentSignatureId
        bytes32 extraMessageDigest; // for confidential documents; Keccak-256 digest
    }

    mapping(uint => Signature) public signatures;
    uint public signatureCount;

    event SignatureCreated(
        uint signatureId,
        uint certificateId,
        string messageDigest,
        bool isContentConfidential,
        bytes32 data,
        uint8 signaturePolicy,
        bytes32 cryptographicSignature,
        bytes20 signerAddress,
        uint parentSignatureId,
        bytes32 extraMessageDigest
    );

    function createSignature(
        uint certificateId,
        string memory messageDigest,
        bool isContentConfidential,
        bytes32 data,
        uint8 signaturePolicy,
        bytes32 cryptographicSignature,
        bytes20 signerAddress,
        uint parentSignatureId,
        bytes32 extraMessageDigest,
        bytes memory publicKey // Public key for signature verification
    ) public {
        // Verify the signature with the provided public key
        require(validateECCSignature(keccak256(abi.encodePacked(messageDigest)), cryptographicSignature, bytes32(uint256(publicKey))), "Signature verification failed");

        // Verify the certificate from the SemiDecPKI contract
        require(semiDecPKI.verifyCertificate(certificateId), "Invalid certificate");

        signatureCount++;
        signatures[signatureCount] = Signature(
            signatureCount,
            certificateId,
            messageDigest,
            isContentConfidential,
            data,
            signaturePolicy,
            cryptographicSignature,
            signerAddress,
            parentSignatureId,
            extraMessageDigest
        );

        emit SignatureCreated(
            signatureCount,
            certificateId,
            messageDigest,
            isContentConfidential,
            data,
            signaturePolicy,
            cryptographicSignature,
            signerAddress,
            parentSignatureId,
            extraMessageDigest
        );
    }
}