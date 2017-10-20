sudo insmod emul-pblk20.ko nr_rwb=8 user_pin=1 wt_pin=1 rb_choice=1 rb_gc_choice=1
sudo modprobe gennvm
sudo lnvm init -d emuld0
sudo lnvm devices
sudo modprobe pblk
sudo lnvm create -d emuld0 -n tgt_emuld0 -t pblk -o 0:0
