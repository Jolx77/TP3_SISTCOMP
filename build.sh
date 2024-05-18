

as -g -o Protected_mode.o Protected_mode.S
ld --oformat binary -o main.img -T link.ld Protected_mode.o
qemu-system-i386 -hda main.img -boot a -s -S -monitor stdio

