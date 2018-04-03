sudo insmod ../emul-14.ko num_lun=4
sudo nvme lnvm list
sudo modprobe pblk
sudo nvme lnvm create -d emuld0 -n tgt_emuld0 -t pblk --lun-begin=0 --lun-end=3 -f
