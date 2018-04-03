for i in {1..10}
do
	./make_tgt_single.sh
	sudo fio ./jobfile/test-1.fio | grep "aggrb" >> ./focssd_result/single_nolock/single_user1.txt
	sudo ./rm_tgt.sh
done

for i in {1..10}
do
	./make_tgt_single.sh
	sudo fio ./jobfile/test-2.fio | grep "aggrb" >> ./focssd_result/single_nolock/single_user2.txt
	sudo ./rm_tgt.sh
done

for i in {1..10}
do
	./make_tgt_single.sh
	sudo fio ./jobfile/test-4.fio | grep "aggrb" >> ./focssd_result/single_nolock/single_user4.txt
	sudo ./rm_tgt.sh
done
for i in {1..10}
do
	./make_tgt_single.sh
	sudo fio ./jobfile/test-8.fio | grep "aggrb" >> ./focssd_result/single_nolock/single_user8.txt
	sudo ./rm_tgt.sh
done

for i in {1..10}
do
	./make_tgt_single.sh
	sudo fio ./jobfile/test-16.fio | grep "aggrb" >> ./focssd_result/single_nolock/single_user16.txt
	sudo ./rm_tgt.sh
done

for i in {1..10}
do
	./make_tgt_single.sh
	sudo fio ./jobfile/test-32.fio | grep "aggrb" >> ./focssd_result/single_nolock/single_user32.txt
	sudo ./rm_tgt.sh
done
