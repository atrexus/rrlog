#include "rbx/offsets.hpp"

#include "native.hpp"

namespace rrlog::rbx
{
    std::unique_ptr< offsets > offsets::_instance = nullptr;

    offsets::offsets( const std::uintptr_t base ) noexcept : _base( base )
    {
    }

    std::unique_ptr< offsets >& offsets::get( ) noexcept
    {
        if ( !_instance )
        {
            _instance = std::unique_ptr< offsets >( new offsets( reinterpret_cast< std::uintptr_t >( GetModuleHandle( nullptr ) ) ) );
        }

        return _instance;
    }
}  // namespace rrlog::rbx