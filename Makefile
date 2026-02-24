all: payload.bin

payload.bin: payload.S payload.ld
	arm-none-eabi-as -mcpu=cortex-m3 -mthumb -o payload.o payload.S
	arm-none-eabi-ld -T payload.ld -o payload.elf payload.o
	arm-none-eabi-objcopy -O binary payload.elf payload.bin

clean:
	rm -rf payload.elf payload.bin

.PHONY: clean
