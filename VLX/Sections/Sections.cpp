#include "Sections.hpp"
#include <VLX/Image.hpp>

bool VLX::Sections::Build( )
{
	std::uint8_t* Sections	   = Image.Raw.data( ) + *( std::uint32_t* )( Image.Raw.data( ) + 0x30 );
	std::uint32_t SectionCount = *( std::uint32_t* )( Image.Raw.data( ) + 0x34 );
	
	if ( !SectionCount )
		return false;
	
	for ( std::uint32_t Index = 0; Index < SectionCount; ++Index )
	{
		std::uint8_t* Section = Sections + Index * 0x0C;
		
		std::uint32_t Rva = *( std::uint32_t* )( Section + 0x04 );
		if ( !Rva )
			return false;

		std::uint32_t Size = *( std::uint32_t* )( Section + 0x08 );
		if ( !Size )
			return false;

		LIEF::PE::Section VLXSection( ".VLX" + std::to_string( Index ) );

		std::vector< std::uint8_t > Content( Image.Raw.data( ) + Rva, Image.Raw.data( ) + Rva + Size );
		VLXSection.content( Content );

		using Characteristics = LIEF::PE::SECTION_CHARACTERISTICS;
		VLXSection.characteristics( std::uint32_t( Characteristics::IMAGE_SCN_MEM_READ 
			| Characteristics::IMAGE_SCN_MEM_WRITE | Characteristics::IMAGE_SCN_MEM_EXECUTE ) );
		
		Image.Binary.add_section( VLXSection );
	}

	return true;
}