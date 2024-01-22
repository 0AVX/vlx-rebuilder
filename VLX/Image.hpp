#pragma once

#include <LIEF/LIEF.hpp>
#include <VLX/Imports/Imports.hpp>
#include <VLX/Sections/Sections.hpp>

namespace VLX
{
	class Image
	{
		std::vector< std::uint8_t > Raw;
		LIEF::PE::Binary Binary = { "pe_from_scratch", LIEF::PE::PE_TYPE::PE32_PLUS };

		friend class Imports;
		friend class Sections;

	public:
		bool Build( const char* Name );

		bool Initialize( const std::string& Path );
	};
}