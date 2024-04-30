all:
	gcc -Werror -Wpedantic -Wall -Wextra main.c -o main
	gcc -Werror -Wpedantic -Wall -Wextra test_syscall_no_root.c -o test_syscall_no_root
	gcc -Werror -Wpedantic -Wall -Wextra prepare_env_test.c -o prepare_env_test
	gcc -Werror -Wpedantic -Wall -Wextra add_test_file_rf.c -o add_test_file_rf
	gcc -Werror -Wpedantic -Wall -Wextra test_files.c -o test_files

clean:
	rm main
	rm test_syscall_no_root
	rm prepare_env_test
	rm add_test_file_rf
	rm test_files
