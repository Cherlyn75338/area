// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.29;

interface IWhitelist {
    ////////////////////////////////////////////////////////////
    //                        Events                          //
    ////////////////////////////////////////////////////////////

    event WhitelistSet(address indexed addr, bool isAddressWhitelisted);

    ////////////////////////////////////////////////////////////
    //                       Functions                        //
    ////////////////////////////////////////////////////////////

    /// @notice Set the address whitelisted status
    /// @param addr The address to add/remove from the whitelist
    /// @param isAddressWhitelisted Whether address should be whitelisted going forward
    function setWhitelisted(address addr, bool isAddressWhitelisted) external;

    /// @notice Checks if the address is whitelisted
    /// @param addr The address to check
    /// @return True if the addr is whitelisted, false otherwise
    function isWhitelisted(address addr) external view returns (bool);

    /// @notice Get all whitelisted addresses
    /// @return An array of all whitelisted addresses
    function getAllWhitelisted() external view returns (address[] memory);
}
