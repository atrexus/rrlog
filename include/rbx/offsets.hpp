#pragma once

#include <cstdint>
#include <memory>

namespace rrlog::rbx
{
    /// <summary>
    /// A singleton class that manages offsets for the Roblox engine.
    /// </summary>
    class offsets
    {
        static std::unique_ptr< offsets > _instance;

        offsets( const std::uintptr_t base, const std::uintptr_t hyperion_base ) noexcept;

        const std::uintptr_t _base;
        const std::uintptr_t _hyperion_base;

        // Offsets in the Roblox client
        static constexpr std::uintptr_t _yr_scanner_ctx = 0x6725CE8;
        static constexpr std::uintptr_t _scanner_match_memory = 0x29FEAE0;
        static constexpr std::uintptr_t _scanner_get_ruleset_string = 0x29FF220;

        // Offsets in Hyperion
        static constexpr std::uintptr_t _global_scan_statistics = 0x2d7530;

       public:
        /// <summary>
        /// Gets/initiates the singleton instance.
        /// </summary>
        /// <returns>A reference to the singleton instance.</returns>
        static std::unique_ptr< offsets >& get( ) noexcept;

        /// <summary>
        /// Returns the address of the YARA scanner context.
        /// </summary>
        __forceinline const std::uintptr_t yr_scanner_ctx( ) const noexcept
        {
            return _base + _yr_scanner_ctx;
        }

        /// <summary>
        /// Returns the absolute address of the `RBX::Scanner::MatchMemory` function.
        /// </summary>
        __forceinline const std::uintptr_t scanner_match_memory( ) const noexcept
        {
            return _base + _scanner_match_memory;
        }

        /// <summary>
        /// Returns the absolute address of the `RBX::Scanner::GetRulesetString` function.
        /// </summary>
        __forceinline const std::uintptr_t scanner_get_ruleset_string( ) const noexcept
        {
            return _base + _scanner_get_ruleset_string;
        }

        /// <summary>
        /// Returns the global scan statistics collected by Hyperion.
        /// </summary>
        __forceinline const std::uintptr_t global_scan_statistics( ) const noexcept
        {
            return _hyperion_base + _global_scan_statistics;
        }
    };
}  // namespace rrlog::rbx