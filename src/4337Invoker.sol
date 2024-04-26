// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { IEntryPoint } from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { IAccount } from "@account-abstraction/contracts/interfaces/IAccount.sol";
import { IAccountExecute } from "@account-abstraction/contracts/interfaces/IAccountExecute.sol";
import { SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS } from "@account-abstraction/contracts/core/Helpers.sol";
import { PackedUserOperation } from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { Auth } from "./3074/Auth.sol";
import { MultiSendAuthCallOnly } from "./3074/MultiSendAuthCallOnly.sol";

/**
 * commit = nonce + calldata
 */
contract Singleton4337Invoker is IAccount, IAccountExecute, Auth, MultiSendAuthCallOnly {
    uint8 internal constant AUTHCALL_IDENTIFIER = 2;

    IEntryPoint private immutable _entryPoint;

    /**
     * Return the entryPoint used by this invoker.
     */
    function entryPoint() public view virtual returns (IEntryPoint) {
        return _entryPoint;
    }

    receive() external payable {}

    constructor(IEntryPoint anEntryPoint) {
        _entryPoint = anEntryPoint;
    }

    function getNonce(address authority) external view returns (uint256) {
        return _entryPoint.getNonce(address(this), uint160(authority));
    }

    /// @inheritdoc IAccount
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external virtual returns (uint256 validationData) {
        _requireFromEntryPoint();
        validationData = _validateSignature(userOp, userOpHash);
        _payPrefund(missingAccountFunds);
    }

    /// @inheritdoc IAccountExecute
    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external {
        _requireFromEntryPoint();

        (address authority, uint64 nonce) = _getAuthorityAndNonce(userOp.nonce);
        (bytes4 selector, bytes memory transactions) = abi.decode(userOp.callData, (bytes4, bytes));
        (bytes32 r, bytes32 s, uint8 v) = _getSignature(userOp.signature);
        auth(authority, userOpHash, v, r, s);
        multiSend(transactions);
    }

    /// @notice Ensure the request comes from the known entrypoint.
    function _requireFromEntryPoint() internal view virtual {
        require(
            msg.sender == address(entryPoint()),
            "account: not from EntryPoint"
        );
    }

    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual returns (uint256 validationData) {
        (address authority,) = _getAuthorityAndNonce(userOp.nonce);
        bytes32 digest = getDigest(userOpHash);
        if (authority != ECDSA.recover(digest, userOp.signature)) {
            return SIG_VALIDATION_FAILED;
        }
        return SIG_VALIDATION_SUCCESS;
    }

    function _payPrefund(uint256 missingAccountFunds) internal virtual {
        if (missingAccountFunds != 0) {
            (bool success, ) = payable(msg.sender).call{
                value: missingAccountFunds,
                gas: type(uint256).max
            }("");
            (success);
            //ignore failure (its EntryPoint's job to verify, not account.)
        }
    }
    
    /// @notice Returns authority and nonce from UserOp.nonce
    function _getAuthorityAndNonce(
        uint256 nonce
    ) internal pure returns (address authority, uint64 nonparallelnonce) {
        authority = address(bytes20(bytes32(nonce << 32)));
        nonparallelnonce = uint64(bytes8(bytes32(nonce << 192)));
    }

    function _getSignature(
        bytes memory signature
    ) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
    }
}
