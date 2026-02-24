ENTRY(blob_entry)

SECTIONS
{
  . = 0;

  .text : ALIGN(4)
  {
    KEEP(*(.text.blob_entry))
    *(.text*)
    *(.rodata*)
  }

  /DISCARD/ :
  {
    *(.comment*)
    *(.note*)
    *(.eh_frame*)
    *(.ARM.exidx*)
    *(.ARM.extab*)
  }
}
