default:
	strace -ttt -v -y -xx -s 33554432 -f -o strace.log ./test-sqlite3.py
	mv test.db test-original.db
	./straplay.py strace.log
	diff test.db test-original.db
	rm strace.log test-original.db test.db
