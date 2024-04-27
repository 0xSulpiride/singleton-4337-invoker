// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@account-abstraction/contracts/interfaces/IAccountExecute.sol";
import "@account-abstraction/contracts/core/EntryPoint.sol";
import "@account-abstraction/contracts/core/EntryPointSimulations.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "@account-abstraction/contracts/samples/SimpleAccountFactory.sol";
import "@account-abstraction/contracts/samples/VerifyingPaymaster.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";
import "forge-std/Vm.sol";
import "../src/4337Invoker.sol";

contract Callee {
    error UnexpectedSender(address expected, address actual);
    event ExpectedSender();

    function expectSender(address expected) public payable {
        if (msg.sender != expected) revert UnexpectedSender(expected, msg.sender);
        emit ExpectedSender();
    }
}

contract EIP4337 is Test {
    using MessageHashUtils for bytes32;

    EntryPoint entryPoint;
    EntryPointSimulations entryPointSimulations;
    SimpleAccountFactory accountFactory;
    SimpleAccount account;
    Singleton4337Invoker invoker;
    VerifyingPaymaster public verifyingPaymaster;
    Callee public callee;

    VmSafe.Wallet public authority;
    VmSafe.Wallet public verifyingSigner;

    address payable beneficiary;
    address user;
    uint256 userKey;

    uint8 AUTHCALL_IDENTIFIER = 2;
    uint48 validUntil = 0;
    uint48 validAfter = 0;

    function setUp() external {
        beneficiary = payable(makeAddr("beneficiary"));
        (user, userKey) = makeAddrAndKey("user");
        entryPoint = new EntryPoint();
        entryPointSimulations = new EntryPointSimulations();
        accountFactory = new SimpleAccountFactory(entryPoint);
        account = accountFactory.createAccount(user, 0);
        invoker = new Singleton4337Invoker(entryPoint);

        callee = new Callee();
        authority = vm.createWallet("authority");
        verifyingSigner = vm.createWallet("verifyingSigner");

        verifyingPaymaster = new VerifyingPaymaster(entryPoint, address(verifyingSigner.addr));
    }

    function testDeploy() external {
        assertEq(address(account.entryPoint()), address(entryPoint));
    }

    function testSimpleUserOp() external {
        // invoker pays for a userop
        vm.deal(address(invoker), 1000 ether);

        // userop.calldata
        bytes memory data = abi.encodeWithSelector(Callee.expectSender.selector, address(authority.addr));
        bytes memory transactions = abi.encodePacked(AUTHCALL_IDENTIFIER, address(callee), uint256(0), data.length, data);

        // signing
        PackedUserOperation memory userOp = fillUserOp(authority.addr, transactions, false);
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes32 digest = invoker.getDigest(userOpHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authority.privateKey, digest);
        userOp.signature = abi.encodePacked(r, s, v);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        vm.expectEmit();
        emit Callee.ExpectedSender();
        entryPoint.handleOps(ops, beneficiary);
    }

    function testWithVerifyingPaymaster() external {
        assertEq(address(invoker).balance, 0);

        // verifying paymaster pays for a userop
        verifyingPaymaster.addStake{value: 1 ether}(1);
        entryPoint.depositTo{value: 1 ether}(address(verifyingPaymaster));

        bytes memory data = abi.encodeWithSelector(Callee.expectSender.selector, address(authority.addr));
        bytes memory transactions = abi.encodePacked(AUTHCALL_IDENTIFIER, address(callee), uint256(0), data.length, data);

        // paymaster signing
        PackedUserOperation memory userOp = fillUserOp(authority.addr, transactions, true);
        bytes memory paymasterSignature = signUserOpPaymaster(verifyingPaymaster, userOp, verifyingSigner.privateKey);
        userOp.paymasterAndData = packPaymasterAndSignature(address(verifyingPaymaster), paymasterSignature);

        // eoa (authority) signing
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        bytes32 digest = invoker.getDigest(userOpHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authority.privateKey, digest);
        userOp.signature = abi.encodePacked(r, s, v);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        
        vm.expectEmit();
        emit Callee.ExpectedSender();
        entryPoint.handleOps(ops, beneficiary);
    }

    function fillUserOp(
        address _authority,
        bytes memory _data,
        bool paymaster
    )
        public
        view
        returns (PackedUserOperation memory op)
    {
        uint128 VGL = 80000 * (paymaster ? 3 : 1);
        uint128 CGL = 50000;
        uint256 PVG = 100000;
        op.sender = address(invoker);
        op.nonce = invoker.getNonce(_authority);
        op.callData = abi.encode(IAccountExecute.executeUserOp.selector, _data);
        op.accountGasLimits = bytes32(abi.encodePacked(bytes16(VGL), bytes16(CGL)));
        op.preVerificationGas = PVG;
        op.gasFees = bytes32(abi.encodePacked(bytes16(uint128(100)), bytes16(uint128(1000000000))));
        if (paymaster) {
            op.paymasterAndData = packPaymasterAndSignature(address(verifyingPaymaster), hex"");
        }
        return op;
    }

    function signUserOpPaymaster(VerifyingPaymaster paymaster, PackedUserOperation memory op, uint256 _key)
        public
        view
        returns (bytes memory signature)
    {
        bytes32 hash = paymaster.getHash(op, validUntil, validAfter);
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_key, hash.toEthSignedMessageHash());
        signature = abi.encodePacked(r, s, v);
    }

    function packPaymasterAndSignature(address paymaster, bytes memory signature) public view returns (bytes memory paymasterAndData) {
        uint256 validationGasLimit = 300000;
        bytes memory paymasterData = abi.encodePacked(uint(validUntil), uint(validAfter), signature);
        bytes32 _gas = bytes32((validationGasLimit << 128) | 0);
        return abi.encodePacked(verifyingPaymaster, _gas, paymasterData);
    }
}