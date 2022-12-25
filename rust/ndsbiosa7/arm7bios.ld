MEMORY {
	BIOS (RWX) : ORIGIN = 0x00000000, LENGTH = 0x4000
}

SECTIONS {
	.text :
	ALIGN(4)
	{
		*(.text .text.*);
	} > BIOS =0

	.rodata :
	ALIGN(4)
	{
		*(.rodata .rodata.*);
		. = ALIGN(4096);
	} > BIOS =0
	
	/DISCARD/ :
	{
		*(*);
	}
}

