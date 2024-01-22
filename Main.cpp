#include "VLX/Image.hpp"

int main( )
{
	VLX::Image VLXModule;
	
	if ( !VLXModule.Initialize( "VLXModule.bin" ) )
		return 0;

	if ( !VLXModule.Build( "VLXModule.dll" ) )
		return 0;

	return 0;
}