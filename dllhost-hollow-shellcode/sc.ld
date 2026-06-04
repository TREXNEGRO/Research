OUTPUT_FORMAT(pei-x86-64)
ENTRY(sc_entry)
SECTIONS {
    . = 0;
    .text : {
        *(.text*)
        *(.rdata*)
        *(.rodata*)
        *(.data*)
    }
    /DISCARD/ : {
        *(.bss*)
        *(.idata*)
        *(.pdata*)
        *(.xdata*)
        *(.reloc*)
        *(.eh_frame*)
        *(.comment*)
        *(.gnu*)
        *(.note*)
    }
}
