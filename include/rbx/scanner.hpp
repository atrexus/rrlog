#pragma once

#include <span>
#include <string>
#include <vector>

namespace rrlog::rbx
{
    /// <summary>
    /// A match result returned by `match_memory`.
    /// </summary>
    struct match_result_t
    {
        std::uint32_t status;
        std::vector< std::uint64_t > ruleset_ids;
    };

    /// <summary>
    /// The memory scan statistics stored in Hyperion. 
    /// </summary>
    struct memory_scan_statistics_t
    {
        std::uint32_t _0;
        std::uint32_t _1;
        std::uint32_t last_scan_ms;
        std::uint32_t _2;
        std::uint32_t total_scan_ms;
        std::uint32_t alloc_bad_cert_count;
        std::uint32_t alloc_neutral_count;
        std::uint32_t alloc_suspicious_count;
        std::uint32_t alloc_likely_malicious_count;
        std::uint32_t alloc_malicious_count;
    };

    /// <summary>
    /// Represents the scanner class. It leverages Roblox's YARA based pattern matching engine to detect suspcious memory loaded in the process.
    /// </summary>
    class scanner
    {
        using match_memory_t = void( __fastcall* )( void*, match_result_t*, const uint8_t*, size_t );
        static match_memory_t _match_memory;

        using get_ruleset_string_t = void( __fastcall* )( std::uintptr_t, std::string*, std::uint32_t );
        static get_ruleset_string_t _get_ruleset_string;

       public:
        /// <summary>
        /// Matches memory against Roblox's custom YARA rulesets.
        /// </summary>
        /// <param name="buffer">The buffer to search</param>
        /// <returns>A new match result</result>
        static match_result_t match_memory( const std::span< std::uint8_t >& buffer ) noexcept;

        /// <summary>
        /// Converts a ruleset ID to a readable string.
        /// </summary>
        static std::string ruleset_to_string( std::uint32_t id ) noexcept;

        /// <summary>
        /// Converts a status code to a readable string.
        /// </summary>
        static std::string status_to_string( std::uint32_t status ) noexcept;

        /// <summary>
        /// Gets the memory scan statistics logged by Hyperion. These are seperate from our scanner, but required for `isDetected`.
        /// </summary>
        static memory_scan_statistics_t statistics( ) noexcept;
    };
}  // namespace rrlog::rbx