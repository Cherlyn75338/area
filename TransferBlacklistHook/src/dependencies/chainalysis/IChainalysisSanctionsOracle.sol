// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.29;

interface IChainalysisSanctionsOracle {
    ////////////////////////////////////////////////////////////
    //                       Functions                        //
    ////////////////////////////////////////////////////////////

    /// @notice Check if an account is sanctioned
    /// @param account The account to check
    /// @return True if the account is sanctioned, false otherwise
    function isSanctioned(address account) external view returns (bool);
}
