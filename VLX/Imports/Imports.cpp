#include "Imports.hpp"
#include <Windows.h>
#include <tlhelp32.h>
#include <filesystem>
#include <VLX/Image.hpp>

std::string VLX::Imports::GetModuleName( std::uint64_t Hash ) const
{
	std::unique_ptr< void, decltype( &CloseHandle ) > 
		Snapshot( CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, GetCurrentProcessId( ) ), &CloseHandle );

	if ( Snapshot.get( ) == INVALID_HANDLE_VALUE )
		return {};

	MODULEENTRY32W ModuleEntry{ .dwSize = sizeof( MODULEENTRY32W ) };
	if ( !Module32FirstW( Snapshot.get( ), &ModuleEntry ) )
		return {};

	do
	{
		std::wstring Name( ModuleEntry.szModule );
		
		if ( this->Hash( ( std::uint8_t* )Name.c_str( ), Name.size( ) * 2 ) == Hash )
			return { Name.begin( ), Name.end( ) };

	} while ( Module32NextW( Snapshot.get( ), &ModuleEntry ) );

	return {};
}

std::string VLX::Imports::GetImportName( const std::unique_ptr< LIEF::PE::Binary >& Binary, std::uint64_t Hash ) const
{
	const auto Exports = Binary->exported_functions( );
	const auto Export = std::find_if( Exports.begin( ), Exports.end( ), [ & ]( const auto& Export )
		{ return this->Hash( ( std::uint8_t* )Export.name( ).c_str( ), Export.name( ).size( ) ) == Hash; } );

	if ( Export == Exports.cend( ) )
		return {};

	return Export->name( );
}

bool VLX::Imports::BuildStubs( )
{
#define PAGE_ALIGN( x ) ( ( x + 0xFFF ) & ~0xFFF )

	std::uint8_t Jump[ 0x06 ]{ 0xFF, 0x25 };
	std::vector< std::uint8_t > Content( Stubs.size( ) * sizeof( Jump ) );
	
	const auto	   LastSection = Image.Binary.sections( ).end( ) - 1;
	std::uintptr_t SectionBase = PAGE_ALIGN( LastSection->virtual_address( ) + LastSection->virtual_size( ) );

	for ( std::size_t Index = 0; Index < Content.size( ); Index += sizeof( Jump ) )
	{
		const auto& Stub = Stubs[ Index / sizeof( Jump ) ];

		std::uintptr_t Import = PAGE_ALIGN( Content.size( ) ) 
			+ Image.Binary.predict_function_rva( Stub.ModuleName, Stub.ImportName );
		
		std::int32_t RipRelative = ( Import - ( SectionBase + Index ) ) - sizeof( Jump );
		*( std::int32_t* )&Jump[ 0x02 ] = RipRelative;
		
		std::memcpy( &Content[ Index ], Jump, sizeof( Jump ) );

		Image.Binary.patch_address( Stub.Address, Image.Binary.imagebase( ) + SectionBase + Index );
	}

	LIEF::PE::Section Section( ".VLXStubs" );
	Section.content( Content );
	
	Image.Binary.add_section( Section, LIEF::PE::PE_SECTION_TYPES::TEXT );

	return true;
}

bool VLX::Imports::Build( )
{
	std::uint32_t NumberOfModules = *( std::uint32_t* )( Image.Raw.data( ) + 0x24 );
	if ( !NumberOfModules )
		return false;

	std::uint8_t* Module = Image.Raw.data( ) + *( std::uint32_t* )( Image.Raw.data( ) + 0x20 );
	for ( std::uint32_t Index = 0; Index < NumberOfModules; ++Index )
	{
		std::uint64_t Hash = *( std::uint64_t* )Module;
		if ( !Hash )
			return false;
		
		std::uint32_t NumberOfImports = *( std::uint32_t* )( Module + 0x0C );
		if ( !NumberOfImports )
			return false;

		std::uint32_t ImportsBase = *( std::uint32_t* )( Module + 0x08 );
		if ( !ImportsBase )
			return false;

		std::string ModuleName = GetModuleName( Hash );
		if ( ModuleName.empty( ) )
			continue;

		Image.Binary.add_library( ModuleName );

		static const auto System32 = std::filesystem::path( std::getenv( "SystemRoot" ) ) / "System32";
		auto			  Binary = LIEF::PE::Parser::parse( ( System32 / ModuleName ).string( ) );

		for ( std::uint32_t Index = 0; Index < NumberOfImports; ++Index)
		{
			std::uint8_t* Import = Module + 0x10 + ( Index * 0x09 );
			if ( *( bool* )Import )
				continue;
			
			std::uint64_t Hash = *( std::uint64_t* )( Import + 0x01 );
			if ( !Hash )
				continue;

			std::string ImportName = GetImportName( Binary, Hash );
			if ( ImportName.empty( ) )
				continue;

			Image.Binary.add_import_function( ModuleName, ImportName );
			Stubs.emplace_back( ModuleName, ImportName, ImportsBase + ( Index * 0x08 ) );
		}

		Module += 0x19 + ( std::uint64_t( NumberOfImports - 1 ) * 0x09 );
	}
	
	return true;
}