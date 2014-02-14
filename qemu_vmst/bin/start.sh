#./qemu -hda ~/fs_traverse/trainning/debian6_encrypt-ff.qcow2  -hdb ~/fs_traverse/trainning/debian6_encrypt-target.qcow2 -m 256  -monitor stdio -net nic,model=rtl8139 -net user -s -redir tcp:5555::22 -loadvm original
#./qemu -hda ~/vmware/Debian\ 6-dm/Debian\ 6-dm.vmdk  -hdb ~/fs_traverse/trainning/debian6_encrypt-target.qcow2 -m 512  -monitor stdio -net nic,model=rtl8139 -net user -s -redir tcp:5555::22 
./qemu -hda ~/debian6-dm.vmdk  -hdb ~/fs_traverse/trainning/debian6_encrypt-target.qcow2 -m 512  -monitor stdio -net nic,model=rtl8139 -net user -s -redir tcp:5555::22 
