// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.13;

import { BaseInvoker } from "../src/3074/BaseInvoker.sol";
import { Script } from "forge-std/Script.sol";

contract Executor is Script {
    // TODO: access transaction signer of forge script
    uint256 pk;

    function signAndExecute(address invoker, bytes memory execData) public {
        // construct the digest from execData
        bytes32 digest = BaseInvoker(invoker).getDigest(execData);
        // sign the digest
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        // broadcast execute transaction
        vm.startBroadcast();
        BaseInvoker(invoker).execute(vm.addr(pk), v, r, s, execData);
        vm.stopBroadcast();
    }
}
