// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.29;

/// @title ICallbackHandler
/// @notice Errors used in the CallbackHandler mixin
interface ICallbackHandler {
    ////////////////////////////////////////////////////////////
    //                         Errors                         //
    ////////////////////////////////////////////////////////////

    /// @notice Thrown when we receive a callback (or a regular call) that wasn't authorized
    error Aera__UnauthorizedCallback();
}
