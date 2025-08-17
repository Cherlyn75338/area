// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.29;

/// @title IHasNumeraire
/// @notice Interface for a contract with a numeraire token
interface IHasNumeraire {
    ////////////////////////////////////////////////////////////
    //                         Errors                         //
    ////////////////////////////////////////////////////////////

    error Aera__ZeroAddressNumeraire();

    ////////////////////////////////////////////////////////////
    //                       Functions                        //
    ////////////////////////////////////////////////////////////

    /// @notice Get the vault's numeraire token
    /// @return The address of the numeraire token
    // solhint-disable-next-line func-name-mixedcase
    function NUMERAIRE() external view returns (address);
}
