./qemu ~/qemu/winxp.qcow2 -m 256  -monitor stdio -net nic,model=rtl8139 -net user -s -redir tcp:5555::22 
