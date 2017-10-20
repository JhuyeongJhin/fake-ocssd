sudo insmod emul-14.ko nr_rwb=8 wt_pin=$1 user_rb_option=$2 gc_rb_option=1 wt_nice=1
sudo nvme lnvm list
sudo modprobe pblk
sudo nvme lnvm create -d emuld0 -n tgt_emuld0 -t pblk --lun-begin=0 --lun-end=3 -f
