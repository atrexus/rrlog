#include "memory.hpp"

#include <vector>

#include "native.hpp"

namespace rrlog
{
    allocation_t get_allocation( const std::uintptr_t address )
    {
        const auto base = reinterpret_cast< PVOID >( address );
        MEMORY_BASIC_INFORMATION mbi{ };
        std::size_t total_size = 0;

        std::uintptr_t ptr = address;
        std::vector< std::pair< std::size_t, std::size_t > > readable_regions;

        while ( VirtualQuery( reinterpret_cast< LPCVOID >( ptr ), &mbi, sizeof( mbi ) ) )
        {
            if ( reinterpret_cast< std::uintptr_t >( mbi.AllocationBase ) != address )
                break;

            const std::size_t region_size = mbi.RegionSize;
            const bool is_committed = ( mbi.State & MEM_COMMIT );
            const bool is_readable = ( mbi.Protect & PAGE_READONLY ) || ( mbi.Protect & PAGE_READWRITE ) || ( mbi.Protect & PAGE_WRITECOPY ) ||
                                     ( mbi.Protect & PAGE_EXECUTE_READ ) || ( mbi.Protect & PAGE_EXECUTE_READWRITE ) ||
                                     ( mbi.Protect & PAGE_EXECUTE_WRITECOPY );
            const bool is_guarded = ( mbi.Protect & PAGE_GUARD ) || ( mbi.Protect & PAGE_NOACCESS );

            if ( is_committed && is_readable && !is_guarded )
            {
                readable_regions.emplace_back( ptr - address, region_size );
            }

            total_size += region_size;
            ptr += region_size;
        }

        auto buffer = std::make_unique< std::uint8_t[] >( total_size );
        std::memset( buffer.get( ), 0, total_size );

        for ( const auto& [ offset, size ] : readable_regions )
        {
            std::memcpy( buffer.get( ) + offset, reinterpret_cast< const void* >( address + offset ), size );
        }

        char module_name[ MAX_PATH ]{ };
        GetModuleFileNameA( reinterpret_cast< HMODULE >( base ), module_name, sizeof( module_name ) );

        allocation_t result{ };
        result.base = address;
        result.size = total_size;
        result.module_path = module_name[ 0 ] ? std::string( module_name ) : std::string{ };
        result.data = std::move( buffer );

        return result;
    }
}  // namespace rrlog