// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.29;

import { IBeforeTransferHook } from "src/core/interfaces/IBeforeTransferHook.sol";

/// @title ITransferBlacklistHook
/// @notice Errors used in the transfer blacklist hook
interface ITransferBlacklistHook is IBeforeTransferHook {
    ////////////////////////////////////////////////////////////
    //                         Errors                         //
    ////////////////////////////////////////////////////////////

    error AeraPeriphery__BlacklistedAddress(address address_);
    error AeraPeriphery__ZeroAddressBlacklistOracle();
}
