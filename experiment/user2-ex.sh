for i in {1..10}
do
	./make_tgt_single.sh
	sudo fio ./jobfile/test-2.fio | grep "aggrb" >> ./focssd_result/single_user2.txt
	sudo ./rm_tgt.sh
done
