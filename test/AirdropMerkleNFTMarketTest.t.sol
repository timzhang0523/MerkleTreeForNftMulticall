// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console, console2} from "forge-std/Test.sol";

import "openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol";
import {DogsToken} from "../src/DogsToken.sol";
import {DogsNFT} from "../src/DogsNFT.sol";
import {AirdropMerkleNFTMarket} from "../src/AirdropMerkleNFTMarket.sol";
import "murky/src/Merkle.sol"; // https://github.com/dmfxyz/murky
import {EIP712Sig} from "../src/EIP712Sig.sol";

// https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/main/solidity/contracts/libs/Merkle.sol

contract AirdropMerkleNFTMarketTest is Test {
    AirdropMerkleNFTMarket internal market;
    DogsNFT public nft;
    DogsToken public token;
    EIP712Sig internal sigUtils;

    Account owner = makeAccount("owner");
    Account alice = makeAccount("alice");
    Account bob = makeAccount("bob");
    Account charlie = makeAccount("charlie");
    Account feeTo = makeAccount("feeTo");

    string internal url = "https://sepolia.etherscan.io/assets/svg/logos/logo-etherscan-light.svg?v=0.0.5";
    uint256 tokenId = 1;
    uint256 price = 1e18;
    uint256 deadline = block.timestamp + 1000;
    bytes32 orderId;
    bytes32[] public merkleProof;
    bytes32[] internal hashData;
    uint256 internal nonce = 0;

    struct User {
        address addr;
        uint256 tokenId;
    }

    User[] public users;
    bytes32[] public elements;

    function setUp() public {
        Merkle m = new Merkle();

        // 初始化用户数据
        users.push(User(alice.addr, 1));
        users.push(User(0xb7D15753D3F76e7C892B63db6b4729f700C01298, 2));
        // users.push(User(0xf69Ca530Cd4849e3d1329FBEC06787a96a3f9A68, 20));
        // users.push(User(0xa8532aAa27E9f7c3a96d754674c99F1E2f824800, 30));

        // 计算哈希值
        computeElements();
        hashData = getElements();
        console2.log("hashData:");
        console.logBytes32(hashData[0]);
        // Get Root, Proof, and Verify
        bytes32 murkyGeneratedRoot = m.getRoot(hashData);
        console2.log("Merkle Root:");
        console.logBytes32(murkyGeneratedRoot);

        merkleProof = m.getProof(hashData, 0); // will get proof for 0x2 value
        for (uint256 i = 0; i < merkleProof.length; i++) {
            console2.log("Merkle proof:");
            console.logBytes32(merkleProof[i]);
        }
        bool verified = m.verifyProof(murkyGeneratedRoot, merkleProof, hashData[0]); // true!
        assertTrue(verified);

        token = new DogsToken(owner.addr);
        nft = new DogsNFT(owner.addr);
        market = new AirdropMerkleNFTMarket(murkyGeneratedRoot);
        sigUtils = new EIP712Sig(token.DOMAIN_SEPARATOR());

        vm.startPrank(owner.addr);
        token.mint(owner.addr, 100 * 10 ** 18);

        nft.safeMint(owner.addr, url);
        // nft.mint(owner.addr);
        vm.stopPrank();
    }

    function testDogsMint() public {
        vm.startPrank(owner.addr); // 0x2
        token.mint(alice.addr, 100 * 10 ** 18);
        token.balanceOf(alice.addr);
        vm.stopPrank();
    }

    function testTokenBalance() public view {
        assertEq(token.balanceOf(owner.addr), 100e18, "owner balance is not 100e18");
        assertEq(token.balanceOf(address(market)), 0, "market balance is not 0");
    }

    function testNFTBalance() public view {
        assertEq(nft.balanceOf(owner.addr), 1, "owner nft balance is not 1");
        assertEq(nft.ownerOf(tokenId), owner.addr, "owner nft is not owner");
    }

    function testListNFT() public {
        vm.startPrank(owner.addr);
        nft.setApprovalForAll(address(market), true);
        assertEq(nft.ownerOf(tokenId), owner.addr, "owner nft is not owner");

        // Check emitted event
        // vm.expectEmit(true, true, false, false);
        // emit AirdropMerkleNFTMarket.List(address(nft), tokenId, orderId, owner.addr, address(token), price, deadline);
        // emit AirdropMerkleNFTMarket.List(address(nft), tokenId, orderId, owner.addr, address(token), price, deadline);
        market.list(address(nft), tokenId, address(token), price, deadline);

        // Compute expected orderId
        AirdropMerkleNFTMarket.SellOrder memory order = AirdropMerkleNFTMarket.SellOrder({
            seller: owner.addr,
            nft: address(nft),
            tokenId: tokenId,
            payToken: address(token),
            price: price,
            deadline: deadline
        });
        bytes32 newOrderId = keccak256(abi.encode(order));

        orderId = market.listing(address(nft), tokenId);
        assertEq(orderId, newOrderId, "order id is not new order id");
        console.log("orderId: ");
        console.logBytes32(orderId);
        // Check listingOrders mapping
        AirdropMerkleNFTMarket.SellOrder memory listedOrder = market.getListingOrders(orderId);
        assertEq(listedOrder.seller, owner.addr);
        assertEq(listedOrder.nft, address(nft));
        assertEq(listedOrder.tokenId, tokenId);
        assertEq(listedOrder.payToken, address(token));
        assertEq(listedOrder.price, price);
        assertEq(listedOrder.deadline, deadline);
        assertEq(nft.getApproved(tokenId), address(0), "NFT not approved correctly");

        vm.stopPrank();
    }

    function testBuyNFT() public {
        vm.startPrank(owner.addr);
        nft.setApprovalForAll(address(market), true);
        market.list(address(nft), tokenId, address(0), price, deadline);
        orderId = market.listing(address(nft), tokenId);
        vm.stopPrank();
        market.setFeeTo(feeTo.addr);
        vm.startPrank(alice.addr);
        vm.deal(alice.addr, 1 ether);
        market.claimNFT{value: 1 ether}(orderId);
        assertEq(nft.ownerOf(tokenId), alice.addr);
        assertEq(feeTo.addr.balance, 0.003 ether);
        vm.stopPrank();
    }

    function testMerkleProofBuyNFT() public {
        vm.startPrank(owner.addr);
        nft.setApprovalForAll(address(market), true);
        market.list(address(nft), tokenId, address(0), price, deadline);
        orderId = market.listing(address(nft), tokenId);
        vm.stopPrank();
        market.setFeeTo(feeTo.addr);
        vm.startPrank(alice.addr);
        console.log("testMerkleProofBuyNFT data:", alice.addr);
        vm.deal(alice.addr, 1 ether);
        market.claimNFT{value: 0.5 ether}(orderId, tokenId, merkleProof);
        assertEq(nft.ownerOf(tokenId), alice.addr);
        assertEq(feeTo.addr.balance, 0 ether);
        vm.stopPrank();
    }

    function testMerkleProofTokenBuyNFT() public {
        vm.startPrank(owner.addr);
        nft.setApprovalForAll(address(market), true);
        market.list(address(nft), tokenId, address(token), price, deadline);
        orderId = market.listing(address(nft), tokenId);

        token.mint(alice.addr, 100 * 10 ** 18);
        vm.stopPrank();
        market.setFeeTo(feeTo.addr);
        vm.startPrank(alice.addr);
        token.approve(address(market), price);
        market.claimNFT(orderId, tokenId, merkleProof);
        assertEq(nft.ownerOf(tokenId), alice.addr);
        assertEq(feeTo.addr.balance, 0 ether);
        vm.stopPrank();
    }

    function testMultiClaimNFT() public {
        bytes[] memory calldatas = new bytes[](2);
        vm.startPrank(owner.addr);
        nft.setApprovalForAll(address(market), true);
        market.list(address(nft), tokenId, address(token), price, deadline);
        orderId = market.listing(address(nft), tokenId);
        token.mint(alice.addr, 100 * 10 ** 18);
        vm.stopPrank();
        market.setFeeTo(feeTo.addr);

        // 3. ERC20 permit
        bytes memory permitSignature = _getEIP2612Signature();

        vm.startPrank(alice.addr);
        //  token.approve(address(market), price);
        calldatas[0] = abi.encodeWithSignature("permitPrePay(bytes32,bytes)", orderId, permitSignature);
        calldatas[1] = abi.encodeWithSignature("claimNFT(bytes32,uint256,bytes32[])", orderId, tokenId, merkleProof);

        vm.deal(alice.addr, 1 ether);
        market.multicall(calldatas);
        assertEq(nft.ownerOf(tokenId), alice.addr);
        assertEq(feeTo.addr.balance, 0 ether);
        vm.stopPrank();
    }

    function _getHashData(bytes32[] memory data) internal returns (bytes32[] memory) {
        // Encode and hash data
        hashData = new bytes32[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            console2.log("Merkle data:");
            console.logBytes32(data[i]);
            hashData[i] = keccak256(abi.encodePacked(data[i]));
        }
        return hashData;
    }

    function computeElements() internal {
        delete elements; // 清空之前的元素

        for (uint256 i = 0; i < users.length; i++) {
            bytes32 element = keccak256(abi.encodePacked(users[i].addr, users[i].tokenId));
            elements.push(element);
        }
    }

    function getElements() public view returns (bytes32[] memory) {
        return elements;
    }

    function _getEIP2612Signature() private view returns (bytes memory) {
        EIP712Sig.Permit memory permit = EIP712Sig.Permit({
            owner: alice.addr,
            spender: address(market),
            value: price,
            nonce: nonce,
            deadline: deadline
        });

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alice.key, digest);
        bytes memory permitSignature = abi.encodePacked(r, s, v);
        return permitSignature;
    }

    function test_Permit() public {
        EIP712Sig.Permit memory permit =
            EIP712Sig.Permit({owner: owner.addr, spender: alice.addr, value: 1e18, nonce: 0, deadline: 1 days});

        bytes32 digest = sigUtils.getTypedDataHash(permit);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.key, digest);

        token.permit(permit.owner, permit.spender, permit.value, permit.deadline, v, r, s);

        assertEq(token.allowance(owner.addr, alice.addr), 1e18);
        assertEq(token.nonces(owner.addr), 1);
    }
}