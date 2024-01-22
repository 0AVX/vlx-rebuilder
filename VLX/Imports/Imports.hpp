#pragma once

#include <LIEF/LIEF.hpp>

namespace VLX
{
	class Image;

	class Imports
	{
		Image& Image;

		struct Stub
		{
			std::string ModuleName;
			std::string ImportName;
			std::uint32_t Address;
		};

		std::vector< Stub > Stubs;

		std::uint64_t Hash( std::uint8_t* Value, std::size_t Size ) const
		{
			std::uint64_t Hash = 0xCBF29CE484222325;

			for ( std::size_t Index = 0; Index < Size; ++Index )
				Hash = 0x100000001B3ull * ( ( *Value++ | 0x20 ) ^ Hash );

			return Hash;
		}

		std::string GetModuleName( std::uint64_t Hash ) const;
		std::string GetImportName( const std::unique_ptr< LIEF::PE::Binary >& Binary, std::uint64_t Hash ) const;

	public:
		Imports( VLX::Image& Image ) : Image( Image ) {}

		bool BuildStubs( );
		bool Build( );
	};
}