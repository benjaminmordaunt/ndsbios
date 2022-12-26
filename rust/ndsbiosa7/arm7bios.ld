MEMORY {
	BIOS (RWX) : ORIGIN = 0x00000000, LENGTH = 0x4000
}

SECTIONS {
	.text :
	{
		. = 0x00001FB4;
		KEEP(*(.text.Blowfish_FeistelRound));
		. = 0x000020BC;
		KEEP(*(.text.Blowfish_Decrypt64));
	} > BIOS =0

	/* Need to figure out exactly where to put
	 * this... */
	.rodata :
	ALIGN(4)
	{
		KEEP(*(.rodata .rodata.*));
		. = ALIGN(4096);
	} > BIOS =0
	
}

