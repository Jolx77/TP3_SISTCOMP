all: real_to_protected

real_to_protected: real_to_protected.asm
	nasm -f bin real_to_protected.asm -o real_to_protected.bin

clean:
	rm -f *.bin