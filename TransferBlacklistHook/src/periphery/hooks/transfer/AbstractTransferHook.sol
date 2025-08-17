// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.29;

import { VaultAuth } from "src/core/VaultAuth.sol";

import { IBeforeTransferHook } from "src/core/interfaces/IBeforeTransferHook.sol";

/// @title IBeforeTransferHook
/// @notice Used in multi-depositor vaults to control whether vault units can be transfered
/// Provides default functionality to disable unit transfers all together for all implementations
abstract contract AbstractTransferHook is IBeforeTransferHook, VaultAuth {
    ////////////////////////////////////////////////////////////
    //                        Storage                         //
    ////////////////////////////////////////////////////////////

    /// @notice Whether the vault units are transferable
    mapping(address vault => bool isVaultUnitTransferable) public isVaultUnitTransferable;

    ////////////////////////////////////////////////////////////
    //              Public / External Functions               //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IBeforeTransferHook
    function setIsVaultUnitsTransferable(address vault, bool isTransferable) external requiresVaultAuth(vault) {
        _setIsVaultUnitsTransferable(vault, isTransferable);
    }

    /// @inheritdoc IBeforeTransferHook
    function beforeTransfer(address from, address to, address transferAgent) public view virtual {
        if (from != transferAgent && to != transferAgent && from != address(0) && to != address(0)) {
            // Check that the vault units are transferable, if the operation is not mint/burn
            require(isVaultUnitTransferable[msg.sender], Aera__VaultUnitsNotTransferable(msg.sender));
        }
    }

    ////////////////////////////////////////////////////////////
    //              Private / Internal Functions              //
    ////////////////////////////////////////////////////////////

    /// @notice Set the vault unit transferable status
    /// @param vault The vault to set the transferable status for
    /// @param isTransferable Whether the vault units are transferable
    function _setIsVaultUnitsTransferable(address vault, bool isTransferable) internal {
        // Effects: set the vault unit transferable status
        isVaultUnitTransferable[vault] = isTransferable;

        // Log the vault unit transferable status set
        emit VaultUnitTransferableSet(vault, isTransferable);
    }
}
