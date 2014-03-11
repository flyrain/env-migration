mv mem_graph.dot mem_graph.dot.bk
mv pemu_log pemu_log.bk
./qemu-1.6.2/build/bin/qemu-system-i386 ~/qemu/winxp.qcow2 -m 512 -loadvm go
