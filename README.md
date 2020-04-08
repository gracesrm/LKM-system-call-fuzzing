# LKM-system-call-fuzzing

fuzz system calls (add perturbations to software execution) through a loadable kernel module

## Key Features

1. fuzz the system calls through a loadable kernel module

* fuzzing area: files, networks, signals and memory
* fuzzing method: 
	* silence system call (w/ and wo/ error return)
	* delay system call
	* buffer manipulation
	* priority decrease

2. adjustable fuzzing/perturbation strength ``THRESHOLD``

3. target software can be any programming language 


## Environment

Linux Ubuntu 12.04


## Example

	# configure the fuzzing strength ``THRESHOLD`` under ``unpred.h``
	# enter the source code folder, and compile
	$ cd lkm-64 
	$ make

	# load the module with target software
	$ sudo insmod hook TARGET="example.exe" 

	# run the target software, and monitor its execution
	$ ./example.exe


## Reference 

* If you enjoy this work, please cite the following.

Sun, R., Sapountzis, N., Yuan, X., Botacin, M., Bishop, M., Porter, D.E., Li, X., Gregio, A. and Oliveira, D., 2020, April. The dose makes the poison—Leveraging uncertainty for effective malware detection. In IEEE Transaction of Dependable and Secure Computing. IEEE.

	@inproceedings{sun2020defense,
	  title={A Praise for Defensive Programming: Leveraging Uncertainty for Effective Malware Mitigation},
	  author={Sun, Ruimin and Sapountzis, Nikolaos and Yuan, Xiaoyong and Botacin, Marcus and Bishop, Matt and Porter, Donald E and Li, Xiaolin and Gregio, Andre and Oliveira, Daniela},
	  booktitle={Transaction of Dependable and Secure Computing, 2020 IEEE},
	  organization={IEEE}
	}

Sun, R., Yuan, X., Lee, A., Bishop, M., Porter, D.E., Li, X., Gregio, A. and Oliveira, D., 2017, August. The dose makes the poison—Leveraging uncertainty for effective malware detection. In Dependable and Secure Computing, 2017 IEEE Conference on (pp. 123-130). IEEE.

	@inproceedings{sun2017dose,
	  title={The dose makes the poison—Leveraging uncertainty for effective malware detection},
	  author={Sun, Ruimin and Yuan, Xiaoyong and Lee, Andrew and Bishop, Matt and Porter, Donald E and Li, Xiaolin and Gregio, Andre and Oliveira, Daniela},
	  booktitle={Dependable and Secure Computing, 2017 IEEE Conference on},
	  pages={123--130},
	  year={2017},
	  organization={IEEE}
	}


## Contact

Ruimin Sun

gracesrm@ufl.edu
