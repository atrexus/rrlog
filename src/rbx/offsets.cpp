#include "rbx/offsets.hpp"

#include "native.hpp"

namespace rrlog::rbx
{
    std::unique_ptr< offsets > offsets::_instance = nullptr;

    offsets::offsets( const std::uintptr_t base, const std::uintptr_t hyperion_base ) noexcept : _base( base ), _hyperion_base( hyperion_base )
    {
    }

    std::unique_ptr< offsets >& offsets::get( ) noexcept
    {
        if ( !_instance )
        {
            const auto base = reinterpret_cast< std::uintptr_t >( GetModuleHandle( nullptr ) );
            const auto hyperion = reinterpret_cast< std::uintptr_t >( GetModuleHandle( "RobloxPlayerBeta.dll" ) );

            _instance = std::unique_ptr< offsets >( new offsets( base, hyperion ) );
        }

        return _instance;
    }
}  // namespace rrlog::rbx