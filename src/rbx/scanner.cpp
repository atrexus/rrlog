#include "rbx/scanner.hpp"

#include "rbx/offsets.hpp"

namespace rrlog::rbx
{
    scanner::match_memory_t scanner::_match_memory = nullptr;
    scanner::get_ruleset_string_t scanner::_get_ruleset_string = nullptr;

    match_result_t scanner::match_memory( const std::span< std::uint8_t >& buffer ) noexcept
    {
        const auto ctx = reinterpret_cast< void* >( offsets::get( )->yr_scanner_ctx( ) );

        if ( !_match_memory )
            _match_memory = reinterpret_cast< match_memory_t >( offsets::get( )->scanner_match_memory( ) );

        match_result_t result{ };
        _match_memory( ctx, &result, buffer.data( ), buffer.size( ) );

        return result;
    }

    std::string scanner::ruleset_to_string( std::uint32_t id ) noexcept
    {
        const auto ctx = offsets::get( )->yr_scanner_ctx( );

        if ( !_get_ruleset_string )
            _get_ruleset_string = reinterpret_cast< get_ruleset_string_t >( offsets::get( )->scanner_get_ruleset_string( ) );

        std::string result{ };
        _get_ruleset_string( ctx, &result, id );

        return result;
    }

    std::string scanner::status_to_string( std::uint32_t status ) noexcept
    {
        switch ( status )
        {
            case 1: return "SCAN_BAD_CERT";
            case 2: return "SCAN_NEUTRAL";
            case 3: return "SCAN_SUSPICIOUS";
            case 4: return "SCAN_LIKELY_MALICIOUS";
            case 5: return "SCAN_MALICIOUS";
        }

        return "SCAN_UKNOWN";
    }
}  // namespace rrlog::rbx