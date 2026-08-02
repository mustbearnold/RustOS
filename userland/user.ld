ENTRY(_start)

PHDRS
{
    text PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = 0x0000008000000000;

    .text : ALIGN(0x1000)
    {
        *(.text .text.* .ltext .ltext.*)
    } :text

    .text.large : ALIGN(0x1000)
    {
        KEEP(*(.ltext.*))
    } :text

    . = ALIGN(0x1000);
    .rodata :
    {
        *(.rodata .rodata.* .lrodata .lrodata.*)
    } :rodata

    . = ALIGN(0x1000);
    .data :
    {
        *(.data .data.* .sdata .sdata.* .got .got.*)
    } :data

    .bss :
    {
        *(.bss .bss.* .sbss .sbss.* COMMON)
    } :data

    /DISCARD/ :
    {
        *(.eh_frame .eh_frame_hdr .comment .note*)
    }
}
