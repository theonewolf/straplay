default:
	strace -ttt -v -y -xx -s 33554432 -f -o strace.log ./test-sqlite3.py 10000
	mv test.db test-original.db
	./straplay.py strace.log
	diff test.db test-original.db
	ls -lah strace.log test.db
	rm strace.log test-original.db test.db
