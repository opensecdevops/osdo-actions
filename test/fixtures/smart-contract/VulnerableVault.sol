// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableVault
 * @dev Test contract with intentional vulnerabilities for osdo-smart-contract-audit testing
 * 
 * OWASP Smart Contract Top 10 vulnerabilities included:
 * - SC01: Reentrancy
 * - SC02: Access Control (missing)
 * - SC05: DoS via unbounded loop
 * - SC06: Bad Randomness
 */
contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalDeposits;
    
    // SC02: No access control modifier
    constructor() {
        owner = msg.sender;
    }
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
    
    // SC01: Reentrancy vulnerability - external call before state update
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // VULNERABLE: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State update AFTER external call - reentrancy risk
        balances[msg.sender] -= amount;
    }
    
    // SC05: DoS via unbounded loop
    address[] public depositors;
    
    function addDepositor(address depositor) external {
        depositors.push(depositor);
    }
    
    // VULNERABLE: Unbounded loop can run out of gas
    function distributeRewards() external {
        for (uint256 i = 0; i < depositors.length; i++) {
            // This loop has no limit and can cause DoS
            balances[depositors[i]] += 1;
        }
    }
    
    // SC06: Bad Randomness - using block.timestamp
    function getRandomNumber() external view returns (uint256) {
        // VULNERABLE: Predictable randomness source
        return uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender)));
    }
    
    // SC02: Missing access control
    function emergencyWithdraw() external {
        // VULNERABLE: No onlyOwner check
        payable(msg.sender).transfer(address(this).balance);
    }
}
