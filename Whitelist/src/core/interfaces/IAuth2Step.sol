// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.29;

/// @title IAuth2Step
/// @notice Interface for the Auth2Step contract
interface IAuth2Step {
    ////////////////////////////////////////////////////////////
    //                         Events                         //
    ////////////////////////////////////////////////////////////

    /// @notice Emitted when ownership transfer is initiated
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);

    ////////////////////////////////////////////////////////////
    //                         Errors                         //
    ////////////////////////////////////////////////////////////

    error Aera__ZeroAddressAuthority();
    error Aera__Unauthorized();

    ////////////////////////////////////////////////////////////
    //                       Functions                        //
    ////////////////////////////////////////////////////////////

    /// @notice Accept ownership transfer
    function acceptOwnership() external;
}
