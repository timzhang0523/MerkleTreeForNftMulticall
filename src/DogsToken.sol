// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.0.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20FlashMint.sol";
import "@openzeppelin/contracts/interfaces/IERC1363Receiver.sol";
import "erc-payable-token/contracts/token/ERC1363/IERC1363Errors.sol";

contract DogsToken is ERC20, ERC20Burnable, Ownable, ERC20Permit, ERC20FlashMint, IERC1363Errors {
    constructor(address initialOwner)
        ERC20("DogsToken", "DNF")
        Ownable(initialOwner)
        ERC20Permit("DogsToken")
    {}

    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }

    function transferAndcall(address to, uint256 value, bytes calldata data) public returns (bool) {
        if (!transfer(to, value)) {
            revert ERC1363TransferFailed(to, value);
        }

        _checkOnTransferReceived(msg.sender, to, value, data);

        return true;
    }

    function _checkOnTransferReceived(address from, address to, uint256 value, bytes memory data) private {
        if (to.code.length == 0) {
            revert ERC1363EOAReceiver(to);
        }

        try IERC1363Receiver(to).onTransferReceived(_msgSender(), from, value, data) returns (bytes4 retval) {
            if (retval != IERC1363Receiver.onTransferReceived.selector) {
                revert ERC1363InvalidReceiver(to);
            }
        } catch (bytes memory reason) {
            if (reason.length == 0) {
                revert ERC1363InvalidReceiver(to);
            } else {
                assembly {
                    revert(add(32, reason), mload(reason))
                }
            }
        }
    }
}