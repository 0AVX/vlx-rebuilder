#include "Image.hpp"
#include <fstream>
#include <VLX/Sections/Sections.hpp>
#include <VLX/Imports/Imports.hpp>

bool VLX::Image::Build( const char* Name )
{
	Sections Sections( *this );
	if ( !Sections.Build( ) )
		return false;

	Imports Imports( *this );
	if ( !Imports.Build( ) )
		return false;

	LIEF::PE::Builder Builder( Binary );
	Builder.build_imports( );

	if ( !Imports.BuildStubs( ) )
		return false;

	Builder.build( );
	Builder.write( Name );

	return true;
}

template < class T >
using Iterator = std::istreambuf_iterator< T >;

bool VLX::Image::Initialize( const std::string& Path )
{
	std::ifstream Stream( Path, std::ios_base::binary );
	Raw = { Iterator< char >( Stream ), Iterator< char >( ) };

	if ( *( std::uint32_t* )Raw.data( ) != 'OTIR' )
		return false;

	std::uint32_t EntryPoint = *( std::uint32_t* )( Raw.data( ) + 0x14 );
	Binary.optional_header( ).addressof_entrypoint( EntryPoint );

	std::uintptr_t ImageBase = *( std::uintptr_t* )( Raw.data( ) + 0x08 );
	Binary.optional_header( ).imagebase( ImageBase );

	return true;
}