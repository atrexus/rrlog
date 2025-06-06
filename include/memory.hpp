#pragma once

#include <memory>
#include <string>
#include <vector>

namespace rrlog
{
    /// <summary>
    /// Represents an allocation of memory. Protection of pages in this allocation may/will differ.
    /// </summary>
    struct allocation_t
    {
        allocation_t( ) = default;

        /// <summary>
        /// The base address of the allocation.
        /// </summary>
        std::uintptr_t base = 0;

        /// <summary>
        /// The size of the allocation in bytes.
        /// </summary>
        std::size_t size = 0;

        /// <summary>
        /// The path to the module backing this memory.
        /// </summary>
        std::string module_path;

        /// <summary>
        /// The buffer containing all readable memory of this allocation.
        /// </summary>
        std::unique_ptr< std::uint8_t[] > data;
    };

    /// <summary>
    /// Gets the `allocation_t` structure from the base address of an allocation.
    /// </summary>
    /// <param name="base">The base address</param>
    /// <returns>The allocation</returns>
    allocation_t get_allocation( const std::uintptr_t base );

    /// <summary>
    /// Gets all allocations that contain at least 10 pages of executable memory.
    /// </summary>
    std::vector< allocation_t > get_executable_allocations( );
}  // namespace rrlog