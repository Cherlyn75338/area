// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.29;

import { IChainalysisSanctionsOracle } from "src/dependencies/chainalysis/IChainalysisSanctionsOracle.sol";

import { AbstractTransferHook } from "src/periphery/hooks/transfer/AbstractTransferHook.sol";

import { IBeforeTransferHook } from "src/core/interfaces/IBeforeTransferHook.sol";
import { ITransferBlacklistHook } from "src/periphery/interfaces/hooks/transfer/ITransferBlacklistHook.sol";

/// @title TransferBlacklistHook
/// @notice Blocks users on a blacklist from transfering vault units in multi-depositor vaults
contract TransferBlacklistHook is AbstractTransferHook, ITransferBlacklistHook {
    ////////////////////////////////////////////////////////////
    //                       Immutables                       //
    ////////////////////////////////////////////////////////////

    /// @notice The blacklist oracle (using Chainalysis sanctions oracle interface)
    IChainalysisSanctionsOracle public immutable BLACKLIST_ORACLE;

    constructor(IChainalysisSanctionsOracle oracle_) {
        // Requirements: check that the oracle is not the zero address
        require(address(oracle_) != address(0), AeraPeriphery__ZeroAddressBlacklistOracle());

        // Effects: set the blacklist oracle
        BLACKLIST_ORACLE = oracle_;
    }

    ////////////////////////////////////////////////////////////
    //              Public / External Functions               //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IBeforeTransferHook
    function beforeTransfer(address from, address to, address transferAgent)
        public
        view
        override(AbstractTransferHook, IBeforeTransferHook)
    {
        super.beforeTransfer(from, to, transferAgent);

        // Check that the `from` and `to` addresses are not sanctioned
        require(from == address(0) || !BLACKLIST_ORACLE.isSanctioned(from), AeraPeriphery__BlacklistedAddress(from));
        require(to == address(0) || !BLACKLIST_ORACLE.isSanctioned(to), AeraPeriphery__BlacklistedAddress(to));
    }
}
