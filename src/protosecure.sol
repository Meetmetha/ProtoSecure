// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IPausable {
    function pause() external;
}

contract ProtoSecure is Ownable, ReentrancyGuard {
    enum SecurityStatus { 
        ACTIVE,      // Protocol is running normally
        SUSPENDED,   // Protocol is paused due to security alert
        RETIRED      // Protocol has been withdrawn from the system
    }
    
    struct ProtocolEntry {
        address protocolAddress;    // Smart contract address of the protocol
        address protocolAdmin;      // Administrator of the protocol
        address securityMediator;   // Assigned security mediator
        uint256 securityDeposit;    // Security deposit amount in Native Token
        SecurityStatus status;      // Current security status
        address activeReporter;     // Address of current security reporter
        uint256 lastUpdateTime;     // Timestamp of last status change
        uint256 lastAlertTime;      // Timestamp of last Alert
        bool isRegistered;          // Registration status
    }
    
    // State variables
    mapping(uint256 => ProtocolEntry) public protocolRegistry;
    uint256 public nextProtocolId = 1;
    uint256 public constant MEDIATOR_TIMEOUT = 3 days;
    
    // Events
    event ProtocolRegistered(
        uint256 indexed protocolId, 
        address indexed protocolAddress, 
        address indexed admin,
        uint256 deposit
    );
    
    event SecurityAlertRaised(
        uint256 indexed protocolId, 
        address indexed reporter,
        uint256 timestamp
    );
    
    event ResolutionCompleted(
        uint256 indexed protocolId,
        uint256 reporterReward,
        uint256 timestamp
    );
    
    event StatusUpdated(
        uint256 indexed protocolId, 
        SecurityStatus newStatus,
        uint256 timestamp
    );
    
    // Constructor
    constructor() Ownable(msg.sender) {
    }
    
    // Modifiers
    modifier onlyMediator(uint256 _protocolId) {
        require(
            msg.sender == protocolRegistry[_protocolId].securityMediator,
            "Only assigned mediator can call this function"
        );
        _;
    }
    
    modifier onlyProtocolAdmin(uint256 _protocolId) {
        require(
            msg.sender == protocolRegistry[_protocolId].protocolAdmin,
            "Only protocol admin can call this function"
        );
        _;
    }
    
    modifier protocolExists(uint256 _protocolId) {
        require(
            protocolRegistry[_protocolId].isRegistered,
            "Protocol not found in registry"
        );
        _;
    }

    // Dapp Creators
    function registerProtocol(
        address _protocolAddress,
        address _mediator
    ) external payable nonReentrant returns (uint256) {
        require(msg.value > 0, "Security deposit required");
        require(_protocolAddress != address(0), "Invalid protocol address");
        require(_mediator != address(0), "Invalid mediator address");
        
        uint256 protocolId = nextProtocolId++;
        
        protocolRegistry[protocolId] = ProtocolEntry({
            protocolAddress: _protocolAddress,
            protocolAdmin: msg.sender,
            securityMediator: _mediator,
            securityDeposit: msg.value,
            status: SecurityStatus.ACTIVE,
            activeReporter: address(0),
            lastUpdateTime: block.timestamp,
            lastAlertTime: 0,
            isRegistered: true
        });
        
        emit ProtocolRegistered(protocolId, _protocolAddress, msg.sender, msg.value);
        return protocolId;
    }

    function retireProtocol(
        uint256 _protocolId
    ) external onlyProtocolAdmin(_protocolId) protocolExists(_protocolId) nonReentrant {
        ProtocolEntry storage protocol = protocolRegistry[_protocolId];
        
        require(protocol.status != SecurityStatus.SUSPENDED, "Cannot retire while suspended");
        
        protocol.status = SecurityStatus.RETIRED;
        protocol.lastUpdateTime = block.timestamp;
        
        payable(protocol.protocolAdmin).transfer(protocol.securityDeposit);
        
        emit StatusUpdated(_protocolId, SecurityStatus.RETIRED, block.timestamp);
    }
    
    function emergencyPause(
        uint256 _protocolId
    ) external onlyProtocolAdmin(_protocolId) protocolExists(_protocolId) nonReentrant {
        ProtocolEntry storage protocol = protocolRegistry[_protocolId];
        
        require(protocol.status == SecurityStatus.ACTIVE, "Protocol must be in ACTIVE state");
        
        IPausable(protocol.protocolAddress).pause();
        protocol.status = SecurityStatus.SUSPENDED;
        protocol.lastUpdateTime = block.timestamp;
        
        emit StatusUpdated(_protocolId, SecurityStatus.SUSPENDED, block.timestamp);
    }
    
    // Hackers submit alert
    function submitSecurityAlert(uint256 _protocolId) external payable nonReentrant protocolExists(_protocolId) {
        ProtocolEntry storage protocol = protocolRegistry[_protocolId];
        
        require(protocol.status == SecurityStatus.ACTIVE, "Protocol must be in ACTIVE state");
        require(msg.value == protocol.securityDeposit, "Must match security deposit amount");
        
        // Pause the protocol
        IPausable(protocol.protocolAddress).pause();
        
        protocol.status = SecurityStatus.SUSPENDED;
        protocol.activeReporter = msg.sender;
        protocol.lastUpdateTime = block.timestamp;
        protocol.lastAlertTime = block.timestamp;
        
        emit SecurityAlertRaised(_protocolId, msg.sender, block.timestamp);
    }
    
    // onlyMediator
    function resolveSecurityAlert(
        uint256 _protocolId, 
        uint256 _reporterShare
    ) external nonReentrant onlyMediator(_protocolId) protocolExists(_protocolId) {
        ProtocolEntry storage protocol = protocolRegistry[_protocolId];

        require(_reporterShare <= 100, "Reporter share must be between 0-100");
        require(protocol.status == SecurityStatus.SUSPENDED, "Protocol must be in SUSPENDED state");
        
        // Calculate rewards
        uint256 totalAmount = protocol.securityDeposit * 2;
        uint256 reporterReward = (totalAmount * _reporterShare) / 100;
        uint256 protocolReturn = totalAmount - reporterReward;
        
        // Set status back to ACTIVE
        protocol.status = SecurityStatus.ACTIVE;
        protocol.lastUpdateTime = block.timestamp;
        
        // Distribute funds
        if (reporterReward > 0) {
            payable(protocol.activeReporter).transfer(reporterReward);
        }
        if (protocolReturn > 0) {
            payable(protocol.protocolAdmin).transfer(protocolReturn);
        }
        
        protocol.activeReporter = address(0);
        
        emit ResolutionCompleted(_protocolId, reporterReward, block.timestamp);
        emit StatusUpdated(_protocolId, SecurityStatus.ACTIVE, block.timestamp);
    }
    
    // View Functions
    function getProtocolDetails(
        uint256 _protocolId
    ) external view returns (ProtocolEntry memory) {
        require(protocolRegistry[_protocolId].isRegistered, "Protocol not found in registry");
        return protocolRegistry[_protocolId];
    }
    
    function getSecurityStatus(
        uint256 _protocolId
    ) external view returns (SecurityStatus) {
        require(protocolRegistry[_protocolId].isRegistered, "Protocol not found in registry");
        return protocolRegistry[_protocolId].status;
    }

    // onlyOwner Emergency
    function forceResolveSecurityAlert(
        uint256 _protocolId, 
        uint256 _reporterShare
    ) external protocolExists(_protocolId) onlyOwner {
        ProtocolEntry storage protocol = protocolRegistry[_protocolId];
        require(
            block.timestamp >= protocol.lastAlertTime + MEDIATOR_TIMEOUT,
            "Mediator timeout not reached"
        );
        require(_reporterShare <= 100, "Reporter share must be between 0-100");
        require(protocol.status == SecurityStatus.SUSPENDED, "Protocol must be in SUSPENDED state");
        
        // Calculate rewards
        uint256 totalAmount = protocol.securityDeposit * 2;
        uint256 reporterReward = (totalAmount * _reporterShare) / 100;
        uint256 protocolReturn = totalAmount - reporterReward;
        
        // Set status back to ACTIVE
        protocol.status = SecurityStatus.ACTIVE;
        protocol.lastUpdateTime = block.timestamp;
        
        // Distribute funds
        if (reporterReward > 0) {
            payable(protocol.activeReporter).transfer(reporterReward);
        }
        if (protocolReturn > 0) {
            payable(protocol.protocolAdmin).transfer(protocolReturn);
        }
        
        protocol.activeReporter = address(0);
        
        emit ResolutionCompleted(_protocolId, reporterReward, block.timestamp);
        emit StatusUpdated(_protocolId, SecurityStatus.ACTIVE, block.timestamp);
    }
}