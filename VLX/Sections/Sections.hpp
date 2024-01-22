#pragma once

namespace VLX
{
	class Image;

	class Sections
	{
		Image& Image;
		
	public:
		Sections( VLX::Image& Image ) : Image( Image ) {}

		bool Build( );
	};
}