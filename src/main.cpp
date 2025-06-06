#include <shlobj.h>

#include <chrono>
#include <format>
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>

#include "memory.hpp"
#include "native.hpp"
#include "rbx/scanner.hpp"

/// <summary>
/// Gets the current timestamp as a string.
/// </summary>
/// <returns>A string representing the current timestamp.</returns>
static std::string get_timestamp( );

/// <summary>
/// Gets the output file path.
/// </summary>
static std::filesystem::path get_file_path( );

static nlohmann::ordered_json scan( const uintptr_t mod );

/// <summary>
/// The real entry point for the DLL.
/// </summary>
static void entry( const std::uintptr_t mod )
{
    MessageBox( nullptr, "Loaded! Please wait a couple of seconds for scanning to complete.", "Success", MB_ICONINFORMATION | MB_OK );

    try
    {
        const auto obj = scan( mod );

        const auto log_file_path = get_file_path( );

        std::ofstream file;
        file.open( log_file_path, std::ios::out | std::ios::app );

        if ( !file.is_open( ) )
            throw std::runtime_error( "Failed to open log file" );

        file << obj.dump( 4 );

        file.close( );

        const auto out_message = std::format( "Scanning complete, dump has been saved to \"{}\".", log_file_path.string( ) );
        MessageBox( nullptr, out_message.c_str( ), "Success", MB_ICONINFORMATION | MB_OK );
    }
    catch ( const std::exception& e )
    {
        MessageBox( nullptr, e.what( ), "Error", MB_ICONERROR | MB_OK );
    }
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD ulReason, LPVOID lpReserved )
{
    if ( ulReason == DLL_PROCESS_ATTACH )
        std::thread( entry, reinterpret_cast< std::uintptr_t >( hModule ) ).detach( );

    return TRUE;
}

std::string get_timestamp( )
{
    auto now = std::chrono::system_clock::now( );
    auto in_time_t = std::chrono::system_clock::to_time_t( now );

    std::tm time_info;
    localtime_s( &time_info, &in_time_t );

    std::ostringstream oss;
    oss << std::put_time( &time_info, "%Y-%m-%d_%H-%M-%S" );
    return oss.str( );
}

std::filesystem::path get_file_path( )
{
    char appdata[ MAX_PATH ];
    if ( SUCCEEDED( SHGetFolderPathA( nullptr, CSIDL_APPDATA, nullptr, 0, appdata ) ) )
    {
        const auto log_dir = std::filesystem::path( appdata ) / "rrlog";
        std::filesystem::create_directories( log_dir );
        return log_dir / ( get_timestamp( ) + ".json" );
    }

    return get_timestamp( ) + ".json";
}

nlohmann::ordered_json scan( const std::uintptr_t mod )
{
    std::vector< nlohmann::ordered_json > result;

    MEMORY_BASIC_INFORMATION mbi{ };
    std::uintptr_t address = 0;

    constexpr std::size_t min_region_size = 0x1000 * 10llu;

    while ( VirtualQuery( ( LPCVOID )address, &mbi, sizeof( mbi ) ) == sizeof( mbi ) )
    {
        bool is_exec = mbi.State == MEM_COMMIT &&
                       ( mbi.Protect & ( PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY ) ) &&
                       !( mbi.Protect & PAGE_GUARD );

        if ( is_exec && mbi.RegionSize >= min_region_size )
        {
            auto allocation = rrlog::get_allocation( reinterpret_cast< std::uintptr_t >( mbi.AllocationBase ) );

            if ( allocation.base > mod || allocation.base + allocation.size < mod )
            {
                nlohmann::ordered_json data;

                if ( allocation.module_path.empty( ) )
                    data[ "file" ] = nullptr;
                else
                    data[ "file" ] = allocation.module_path;

                data[ "start" ] = std::format( "{:#x}", allocation.base );
                data[ "end" ] = std::format( "{:#x}", allocation.base + allocation.size );
                data[ "size" ] = allocation.size;

                const auto& match = rrlog::rbx::scanner::match_memory( { allocation.data.get( ), allocation.size } );

                data[ "status" ] = rrlog::rbx::scanner::status_to_string( match.status );
                data[ "statusCode" ] = match.status;

                std::vector< nlohmann::ordered_json > matched_rulesets;

                for ( std::size_t i = 0; i + 1 < match.ruleset_ids.size( ); i += 2 )
                {
                    nlohmann::ordered_json obj;

                    const auto rid = static_cast< std::uint32_t >( match.ruleset_ids[ i ] );

                    obj[ "id" ] = rid;

                    const auto s = rrlog::rbx::scanner::ruleset_to_string( rid );

                    obj[ "name" ] = s;

                    matched_rulesets.push_back( obj );
                }

                data[ "matched" ] = matched_rulesets;

                result.push_back( data );
            }

            address = allocation.base + allocation.size;
        }
        else
            address = ( std::uintptr_t )mbi.BaseAddress + mbi.RegionSize;

        if ( address < ( std::uintptr_t )mbi.BaseAddress )
            break;
    }

    return result;
}
