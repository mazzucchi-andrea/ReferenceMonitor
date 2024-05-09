all:
	gcc -Werror -Wpedantic -Wall -Wextra main.c -o main
	gcc -Werror -Wpedantic -Wall -Wextra test_syscall_no_root.c -o test_syscall_no_root
	gcc -Werror -Wpedantic -Wall -Wextra prepare_env_test.c -o prepare_env_test
	gcc -Werror -Wpedantic -Wall -Wextra add_test_file_rf.c -o add_test_file_rf
	gcc -Werror -Wpedantic -Wall -Wextra add_test_dir_rf.c -o add_test_dir_rf
	gcc -Werror -Wpedantic -Wall -Wextra remove_test_file_rf.c -o remove_test_file_rf
	gcc -Werror -Wpedantic -Wall -Wextra remove_test_dir_rf.c -o remove_test_dir_rf
	gcc -Werror -Wpedantic -Wall -Wextra test_files.c -o test_files
	gcc -Werror -Wpedantic -Wall -Wextra test_dir.c -o test_dir

clean:
	rm main
	rm test_syscall_no_root
	rm prepare_env_test
	rm add_test_file_rf
	rm add_test_dir_rf
	rm remove_test_file_rf
	rm remove_test_dir_rf
	rm test_files
	rm test_dir
