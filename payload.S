.syntax unified
.thumb
.global blob_entry
.type blob_entry, %function
.section .text.blob_entry, "ax", %progbits

.equ BUF_ADDR,    0x08000000
.equ BUF_LEN,     0x20000

.equ USART_BASE,  0x40004400      /* USART2 base register */

.equ SR_TXE_BIT,  (1<<7)          /* USART_SR.TXE: TX data register empty */

.equ IWDG_KR,      0x40003000     /* IWDG key register address (KR) */
.equ IWDG_RELOAD,  0xAAAA         /* reload key: resets watchdog counter */

blob_entry:
    cpsid i                       /* Disable all maskable interrupts */

    ldr   r2, =USART_BASE         /* r2 = USART2 base */
    ldr   r0, =BUF_ADDR           /* r0 = buffer pointer */
    ldr   r1, =BUF_LEN            /* r1 = length */

    ldr   r4, =IWDG_KR            /* r4 = &IWDG_KR (fixed address) */
    ldr   r5, =IWDG_RELOAD        /* r5 = 0xAAAA reload key */

1:  cbz   r1, 3f                  /* if len == 0, done */

2:  str   r5, [r4, #0]            /* IWDG_KR = 0xAAAA (kick watchdog) */
    ldr   r3, [r2, #0]            /* r3 = USART_SR */
    tst   r3, #SR_TXE_BIT         /* TXE set? */
    beq   2b                      /* wait until TXE==1 */

    ldrb  r3, [r0], #1            /* r3 = *buf++ */
    str   r3, [r2, #4]            /* USART_DR = byte */

    subs  r1, r1, #1              /* len-- */
    b     1b

3:  str   r5, [r4, #0]            /* IWDG_KR = 0xAAAA (kick watchdog) */
    b     3b                      /* forever loop */

.size blob_entry, .-blob_entry
