// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal, self-contained equivalents of OpenZeppelin ReentrancyGuard and Ownable.
// The fixture compiles without npm dependencies, so scanners run on it as-is.

abstract contract ReentrancyGuard {
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status = _NOT_ENTERED;

    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
}

abstract contract Ownable {
    address private _owner;

    constructor(address initialOwner) {
        _owner = initialOwner;
    }

    modifier onlyOwner() {
        require(_owner == msg.sender, "Ownable: caller is not the owner");
        _;
    }

    function owner() public view returns (address) {
        return _owner;
    }
}

/**
 * @title SecureVault
 * @dev Secure contract following OWASP Smart Contract best practices
 */
contract SecureVault is ReentrancyGuard, Ownable {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    
    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    
    constructor() Ownable(msg.sender) {}
    
    function deposit() external payable {
        require(msg.value > 0, "Amount must be positive");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }
    
    // SC01: Protected against reentrancy with modifier
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // State update BEFORE external call
        balances[msg.sender] -= amount;
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit Withdrawn(msg.sender, amount);
    }
    
    // SC02: Proper access control with onlyOwner
    function emergencyWithdraw() external onlyOwner {
        payable(owner()).transfer(address(this).balance);
    }
}
