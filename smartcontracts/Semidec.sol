// SPDX-License-Identifier: Hacettepe Wise Lab
pragma solidity ^0.8.0;

contract ERC20Token {
    mapping(address => uint256) public balanceOf;

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        return true;
    }
}

contract SemiDecPKI {
    struct Certificate {
        uint64 certificateId;
        uint64 serialNumber;
        bool includeTransactionKey;
        string subjectIdentity;
        uint8 certificateType;
        bytes32 publicKey;
        uint64 issuerCertId;
        uint32 expirationDate;
        address ownerAddress;
        address issuerAddress;
        bytes32 audit;
        bytes32[2] cryptographicSignature;
        uint8 positiveVotersCount;
        uint8 negativeVotersCount;
        mapping(address => bool) positiveVoters;
        mapping(address => bool) negativeVoters;
        bool revocationStatus;
        uint32 waitingTime;
        bool isAccepted; // Added field to track acceptance status
        uint8 totalVotes; // Added field to track the total number of votes
        bytes32 X509Address;
    }

    mapping(uint64 => Certificate) public certificates;
    uint64 public certificateCounter;
    uint8 public votingThreshold; // Added variable to store the voting threshold
    address public owner; // Added variable to store the contract owner
    uint256 public totalStakedTokens; // Total ERC20 tokens staked in the contract

    ERC20Token public erc20Token; // Reference to the ERC20 token contract
    mapping(address => uint256) public stakedTokens; // ERC20 tokens staked by each address
    mapping(uint64 => mapping(address => bool)) public hasVoted; // Track if an address has voted for a certificate

    event CertificateRegistered(uint64 certificateId, address ownerAddress);
    event CertificateRevoked(uint64 certificateId, address revokerAddress);
    event VoteCasted(uint64 certificateId, address voter, bool isPositiveVote);
    event CertificateAccepted(uint64 certificateId); // New event for certificate acceptance
    event FraudReported(uint64 certificateId, address auditor); // New event for fraud reporting
    event TokensStaked(address staker, uint256 amount);
    event RewardDistributed(address recipient, uint256 amount);

    constructor(address _erc20TokenAddress, uint8 _votingThreshold) {
        erc20Token = ERC20Token(_erc20TokenAddress);
        votingThreshold = _votingThreshold;
        owner = msg.sender; // Initialize the contract owner
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the contract owner can call this function");
        _;
    }

    function registerCertificate(
        uint64 _serialNumber,
        bool _includeTransactionKey,
        string memory _subjectIdentity,
        uint8 _certificateType,
        bytes32 _publicKey,
        uint64 _issuerCertId,
        uint32 _expirationDate,
        address _ownerAddress,
        address _issuerAddress,
        bytes32 _audit,
        bytes32[2] memory _cryptographicSignature,
        uint32 _waitingTime
    ) public {
        certificates[certificateCounter] = Certificate(
            certificateCounter,
            _serialNumber,
            _includeTransactionKey,
            _subjectIdentity,
            _certificateType,
            _publicKey,
            _issuerCertId,
            _expirationDate,
            _ownerAddress,
            _issuerAddress,
            _audit,
            _cryptographicSignature,
            0,
            0,
            new bytes32 ,
            new bytes32 ,
            false,
            _waitingTime,
            false, // Initialize as not accepted
            0 // Initialize totalVotes to 0
        );
        emit CertificateRegistered(certificateCounter, _ownerAddress);
        certificateCounter++;
    }

    function revokeCertificate(uint64 _certificateId) public {
        require(_certificateId < certificateCounter, "Certificate does not exist");
        require(msg.sender == certificates[_certificateId].ownerAddress, "Only the owner can revoke");
        require(certificates[_certificateId].positiveVotersCount < certificates[_certificateId].negativeVotersCount, "Cannot revoke with more positive votes");

        certificates[_certificateId].revocationStatus = true;
        emit CertificateRevoked(_certificateId, msg.sender);
    }

    function stakeTokens(uint256 _amount) public {
        require(_amount > 0, "Amount must be greater than 0");
        require(erc20Token.transferFrom(msg.sender, address(this), _amount), "Token transfer failed");
        
        stakedTokens[msg.sender] += _amount;
        totalStakedTokens += _amount;
        emit TokensStaked(msg.sender, _amount);
    }

function issueCertificate(
    uint64 _certificateId,
    address _issuerAddress,
    uint256 _stakeAmount
) public {
    require(_certificateId < certificateCounter, "Certificate does not exist");
    require(msg.sender == _issuerAddress, "Only the issuer can issue a certificate");

    // Perform smart contract-based controls here
    // If controls pass, stake ERC tokens
    require(_stakeAmount > 0, "Stake amount must be greater than 0");
    require(erc20Token.transferFrom(msg.sender, address(this), _stakeAmount), "Token transfer failed");
    stakedTokens[msg.sender] += _stakeAmount;
    totalStakedTokens += _stakeAmount;

    // Ensure all required fields are provided
    Certificate storage cert = certificates[_certificateId];
    require(cert.certificateId != 0, "Certificate ID must be provided");
    require(cert.serialNumber != 0, "Serial number must be provided");
    require(bytes(cert.subjectIdentity).length > 0, "Subject identity must be provided");
    require(cert.certificateType != 0, "Certificate type must be provided");
    require(cert.publicKey != bytes32(0), "Public key must be provided");
    require(cert.issuerCertId != 0, "Issuer certificate ID must be provided");
    require(cert.expirationDate != 0, "Expiration date must be provided");
    require(cert.ownerAddress != address(0), "Owner address must be provided");
    require(cert.issuerAddress != address(0), "Issuer address must be provided");
    require(cert.audit != bytes32(0), "Audit must be provided");
    require(cert.cryptographicSignature[0] != bytes32(0) && cert.cryptographicSignature[1] != bytes32(0), "Cryptographic signature must be provided");

    // Once the controls are successful and ERC tokens are staked, start the voting process
    castVote(_certificateId, true);
}



    function castVote(uint64 _certificateId, bool _isPositiveVote) public {
        require(_certificateId < certificateCounter, "Certificate does not exist");
        require(!certificates[_certificateId].revocationStatus, "Cannot vote on a revoked certificate");
        require(msg.sender != certificates[_certificateId].ownerAddress, "Owners cannot vote on their own certificate");
        require(!certificates[_certificateId].isAccepted, "Certificate already accepted");
        require(stakedTokens[msg.sender] > 0, "Must stake tokens to vote");
        require(!hasVoted[_certificateId][msg.sender], "Already voted");

        if (_isPositiveVote) {
            certificates[_certificateId].positiveVoters[msg.sender] = true;
            certificates[_certificateId].positiveVotersCount++;
        } else {
            certificates[_certificateId].negativeVoters[msg.sender] = true;
            certificates[_certificateId].negativeVotersCount++;
        }

        certificates[_certificateId].totalVotes++;
        hasVoted[_certificateId][msg.sender] = true;

        emit VoteCasted(_certificateId, msg.sender, _isPositiveVote);

        // Check if the voting threshold is reached
        if (certificates[_certificateId].totalVotes >= votingThreshold) {
            certificates[_certificateId].isAccepted = true;
            emit CertificateAccepted(_certificateId);

            // Distribute rewards to voters
            distributeRewards(_certificateId);
        }
    }

    function distributeRewards(uint64 _certificateId) internal {
        uint256 totalPositiveVotes = certificates[_certificateId].positiveVotersCount;
        uint256 totalNegativeVotes = certificates[_certificateId].negativeVotersCount;
        uint256 totalTokens = totalStakedTokens;

        // Distribute rewards to positive voters
        for (uint i = 0; i < totalPositiveVotes; i++) {
            address positiveVoter = getPositiveVoter(_certificateId, i);
            uint256 reward = (stakedTokens[positiveVoter] * totalTokens) / totalPositiveVotes;
            erc20Token.transfer(positiveVoter, reward);
            emit RewardDistributed(positiveVoter, reward);
        }

        // Distribute rewards to negative voters
        for (uint i = 0; i < totalNegativeVotes; i++) {
            address negativeVoter = getNegativeVoter(_certificateId, i);
            uint256 reward = (stakedTokens[negativeVoter] * totalTokens) / totalNegativeVotes;
            erc20Token.transfer(negativeVoter, reward);
            emit RewardDistributed(negativeVoter, reward);
        }

        // Return staked tokens to the certificate issuer
        uint256 issuerStake = stakedTokens[msg.sender];
        stakedTokens[msg.sender] = 0;
        totalStakedTokens -= issuerStake;
        erc20Token.transfer(msg.sender, issuerStake);
        emit TokensReturned(msg.sender, issuerStake);
    }

    function getPositiveVoter(uint64 _certificateId, uint256 index) internal view returns (address) {
        uint256 count = 0;
        Certificate storage cert = certificates[_certificateId];
        for (uint i = 0; i < stakedTokens.length; i++) {
            if (cert.positiveVoters[stakedTokens[i]]) {
                if (count == index) {
                    return stakedTokens[i];
                }
                count++;
            }
        }
        revert("Positive voter not found");
    }

    function getNegativeVoter(uint64 _certificateId, uint256 index) internal view returns (address) {
        uint256 count = 0;
        Certificate storage cert = certificates[_certificateId];
        for (uint i = 0; i < stakedTokens.length; i++) {
            if (cert.negativeVoters[stakedTokens[i]]) {
                if (count == index) {
                    return stakedTokens[i];
                }
                count++;
            }
        }
        revert("Negative voter not found");
    }
}