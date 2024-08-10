// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/mocks/EIP712Verifier.sol";
// https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/MerkleProof.sol
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/utils/Multicall.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {Script, console} from "forge-std/Script.sol";

contract AirdropMerkleNFTMarket is Ownable, IERC721Receiver, EIP712Verifier {
    bytes32 public merkleRoot;
    address public constant ETH_FLAG = address(0);
    uint256 public constant feeBP = 30; // 30/10000 = 0.3%
    uint256 public constant DISCOUNT_BP = 5000; // 50% discount (5000/10000)

    address public feeTo;
    mapping(bytes32 => SellOrder) public listingOrders; // orderId -> order book
    mapping(address => mapping(uint256 => bytes32)) private _lastIds; //  nft -> lastOrderId

    struct SellOrder {
        address seller;
        address nft;
        uint256 tokenId;
        address payToken;
        uint256 price;
        uint256 deadline;
    }

    constructor(bytes32 merkleRoot_) Ownable(msg.sender) EIP712("NFTMarket", "1") {
        merkleRoot = merkleRoot_;
    }

    function list(address nft, uint256 tokenId, address payToken, uint256 price, uint256 deadline) external {
        require(deadline > block.timestamp, "MKT: deadline is in the past");
        require(price > 0, "MKT: price is zero");
        require(payToken == address(0) || IERC20(payToken).totalSupply() > 0, "MKT: payToken is not valid");

        // safe check
        require(IERC721(nft).ownerOf(tokenId) == msg.sender, "MKT: not owner");
        require(
            IERC721(nft).getApproved(tokenId) == address(this)
                || IERC721(nft).isApprovedForAll(msg.sender, address(this)),
            "MKT: not approved"
        );

        SellOrder memory order = SellOrder({
            seller: msg.sender,
            nft: nft,
            tokenId: tokenId,
            payToken: payToken,
            price: price,
            deadline: deadline
        });

        bytes32 orderId = keccak256(abi.encode(order));
        // safe check repeat list
        require(listingOrders[orderId].seller == address(0), "MKT: order already listed");
        listingOrders[orderId] = order;
        _lastIds[nft][tokenId] = orderId; // reset
        emit List(nft, tokenId, orderId, msg.sender, payToken, price, deadline);
    }

    function listing(address nft, uint256 tokenId) external view returns (bytes32) {
        // 获取nft和tokenId对应的id
        bytes32 id = _lastIds[nft][tokenId];
        // 如果listingOrders中id对应的seller地址为0，则返回bytes32(0x00)，否则返回id
        return listingOrders[id].seller == address(0) ? bytes32(0x00) : id;
    }

    // 确保 listingOrders 函数返回 SellOrder 类型
    function getListingOrders(bytes32 orderId) external view returns (SellOrder memory) {
        return listingOrders[orderId];
    }

    function cancel(bytes32 orderId) external {
        address seller = listingOrders[orderId].seller;
        // safe check repeat list
        require(seller != address(0), "MKT: order not listed");
        require(seller == msg.sender, "MKT: only seller can cancel");
        delete listingOrders[orderId];
        emit Cancel(orderId);
    }

    function permitPrePay(bytes32 orderId, bytes memory permit2612Signature) public {
        SellOrder memory order = listingOrders[orderId];
        require(order.seller != address(0), "MKT: order not listed");
        require(order.deadline > block.timestamp, "MKT: order expired");

        bytes32 r;
        bytes32 s;
        uint8 v;
        // ecrecover takes the signature parameters, and the only way to get them
        // currently is to use assembly.
        /// @solidity memory-safe-assembly
        assembly {
            r := mload(add(permit2612Signature, 0x20))
            s := mload(add(permit2612Signature, 0x40))
            v := byte(0, mload(add(permit2612Signature, 0x60)))
        }
        IERC20Permit(order.payToken).permit(msg.sender, address(this), order.price, order.deadline, v, r, s);
    }

    function claimNFT(bytes32 orderId) public payable {
        _buy(orderId, feeTo);
    }

    function claimNFT(bytes32 orderId, uint256 tokenId, bytes32[] calldata merkleProof) external payable {
        // Verify the merkle proof.
        bytes32 node = keccak256(abi.encodePacked(msg.sender, tokenId));

        require(_verifyWhitelistProof(merkleProof, node), "MerkleDistributor: Invalid proof.");
        _buy(orderId, address(0));
    }

    // function multiClaimNFT(
    //     bytes32 orderId,
    //     uint256 tokenId,
    //     bytes32[] calldata merkleProof,
    //     bytes memory permit2612Signature
    // ) external payable returns (bytes[] memory results) {
    //     // a batch of 4 function calls:
    //     // 1. add(5): return ""
    //     // 2. getNumber(): return 0+5

    //     bytes[] memory calldatas = new bytes[](2);
    //     // calldatas[0] = abi.encodeCall(permitPrePay, (orderId, permit2612Signature));
    //     // calldatas[1] = abi.encodeCall(claimNFT, (orderId, tokenId, merkleProof));

    //     // multicall(calldatas);
    //     // calldatas[0] = abi.encodeWithSignature("permitPrePay(bytes32,bytes)", orderId, permit2612Signature);
    //     // calldatas[1] = abi.encodeWithSignature("claimNFT(bytes32,uint256,bytes32[])", orderId, tokenId, merkleProof);

    //     // // Call the multicall function
    // }

    function multicall(bytes[] calldata data) external payable returns (bytes[] memory results) {
        bytes memory context =
            msg.sender == _msgSender() ? new bytes(0) : msg.data[msg.data.length - _contextSuffixLength():];

        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            results[i] = Address.functionDelegateCall(address(this), bytes.concat(data[i], context));
        }
        return results;
    }

    function _verifyWhitelistProof(bytes32[] calldata merkleProof, bytes32 leaf) internal view returns (bool) {
        return MerkleProof.verify(merkleProof, merkleRoot, leaf);
    }

    function _buy(bytes32 orderId, address feeReceiver) private {
        // 0. load order info to memory for check and read
        SellOrder memory order = listingOrders[orderId];

        // 1. check
        require(order.seller != address(0), "MKT: order not listed");
        require(order.deadline > block.timestamp, "MKT: order expired");

        // Apply discount for white-listed users
        uint256 finalPrice = feeReceiver == address(0) ? (order.price * (10000 - DISCOUNT_BP)) / 10000 : order.price;

        // 2. remove order info before transfer
        delete listingOrders[orderId];
        // 3. trasnfer NFT
        IERC721(order.nft).safeTransferFrom(order.seller, msg.sender, order.tokenId);

        // 4. trasnfer token
        // fee 0.3% or 0
        uint256 fee = feeReceiver == address(0) ? 0 : (finalPrice * feeBP) / 10000;
        // safe check
        if (order.payToken == ETH_FLAG) {
            require(msg.value == finalPrice, "MKT: wrong eth value");
        } else {
            require(msg.value == 0, "MKT: ETH value should be zero");
        }
        _transferOut(order.payToken, order.seller, finalPrice - fee);
        if (fee > 0) _transferOut(order.payToken, feeReceiver, fee);

        emit Sold(orderId, msg.sender, fee);
    }

    function _transferOut(address token, address to, uint256 amount) private {
        if (token == ETH_FLAG) {
            // eth
            (bool success,) = to.call{value: amount}("");
            require(success, "MKT: transfer fee failed");
        } else {
            SafeERC20.safeTransferFrom(IERC20(token), msg.sender, to, amount);
        }
    }

    function setFeeTo(address to) external onlyOwner {
        require(feeTo != to, "MKT:repeat set");
        feeTo = to;

        emit SetFeeTo(to);
    }

    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        external
        returns (bytes4)
    {
        require(operator == msg.sender, " invalid operator");
        require(operator == from, " invalid operator");
        require(from != address(0), "zero address");
        uint256 price = abi.decode(data, (uint256));

        SellOrder memory order = SellOrder({
            seller: from,
            nft: operator,
            tokenId: tokenId,
            payToken: ETH_FLAG,
            price: price,
            deadline: block.timestamp + 1 days
        });
        bytes32 orderId = keccak256(abi.encode(order));
        // safe check repeat list
        require(listingOrders[orderId].seller == address(0), "MKT: order already listed");
        listingOrders[orderId] = order;
        _lastIds[operator][tokenId] = orderId; // reset
        emit List(operator, tokenId, orderId, msg.sender, ETH_FLAG, price, block.timestamp + 1 days);

        return this.onERC721Received.selector;
    }

    function setMerkleRoot(bytes32 _merkleRoot) external onlyOwner {
        merkleRoot = _merkleRoot;
    }

    event List(
        address indexed nft,
        uint256 indexed tokenId,
        bytes32 orderId,
        address seller,
        address payToken,
        uint256 price,
        uint256 deadline
    );

    event Sold(bytes32 orderId, address buyer, uint256 fee);
    event SetFeeTo(address to);
    event Cancel(bytes32 orderId);
}