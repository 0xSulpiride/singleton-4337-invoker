// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@account-abstraction/contracts/interfaces/IAccountExecute.sol";
import "@account-abstraction/contracts/core/EntryPoint.sol";
import "@account-abstraction/contracts/core/EntryPointSimulations.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "@account-abstraction/contracts/samples/SimpleAccountFactory.sol";
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
    EntryPoint entryPoint;
    EntryPointSimulations entryPointSimulations;
    SimpleAccountFactory accountFactory;
    SimpleAccount account;
    Singleton4337Invoker invoker;
    Callee public callee;

    VmSafe.Wallet public authority;

    address payable beneficiary;
    address user;
    uint256 userKey;

    uint8 AUTHCALL_IDENTIFIER = 2;

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

        vm.deal(address(invoker), 1000 ether);
    }

    function testDeploy() external {
        assertEq(address(account.entryPoint()), address(entryPoint));
    }

    function testSimpleUserOp() external {
        // calldata
        bytes memory data = abi.encodeWithSelector(Callee.expectSender.selector, address(authority.addr));
        bytes memory transactions = abi.encodePacked(AUTHCALL_IDENTIFIER, address(callee), uint256(0), data.length, data);

        // signing
        PackedUserOperation memory userOp = fillUserOp(authority.addr, transactions);
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
        bytes memory _data
    )
        public
        view
        returns (PackedUserOperation memory op)
    {
        op.sender = address(invoker);
        op.nonce = invoker.getNonce(_authority);
        op.callData = abi.encode(IAccountExecute.executeUserOp.selector, _data);
        op.accountGasLimits = bytes32(abi.encodePacked(bytes16(uint128(80000)), bytes16(uint128(50000))));
        op.preVerificationGas = 50000;
        op.gasFees = bytes32(abi.encodePacked(bytes16(uint128(100)), bytes16(uint128(1000000000))));
        return op;
    }
}