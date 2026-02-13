# Bandit Levels 0-20
This repository contains my walkthroughs for the OverTheWire Bandit wargame, levels 0 through 20. Each level includes the goal, my process for solving it, and a takeaway highlighting what the level teaches. The notes focus on command-line techniques, file handling, encoding/decoding, SSH and networking basics, and privilege escalation concepts.

## Level Zero  
### Goal  
The goal of this level is to log into the game using SSH. The host you need to connect to is `bandit.labs.overthewire.org`, on port 2220. The username is `bandit0` and the password is `bandit0`. Once logged in, go to the Level 1 page to find out how to beat Level 1.

### Process  
Challenge zero was simple. I input the command:  
`ssh bandit0@bandit.labs.overthewire.org -p 2220`

Once I used SSH to get into the lab, it prompted me for the password that was provided in the login instructions. From here, I used the command:  
`ls`

This allowed me to see what was available, which revealed a "readme" file. Using:  
`cat readme`

I was able to read the file and obtain the password for the first official level.

### Takeaways  
This level teaches the basics of connecting to a remote server with SSH and exploring the file system to locate important information.

## Level One  
### Goal  
The password for the next level is stored in a file called `-` located in the home directory.

### Process  
For this one, the hint told me that the file was in the home directory of `bandit1`, so as soon as I got in with SSH, I ran the command:  
`ls -la`

This showed me everything in the current directory, including hidden files. Immediately, at the top, the `-` file was visible. Using `cat -` would not work because the terminal interprets `-` as an option rather than a file name. Instead, I used:  
`cat ./-`

This revealed the file's contents and gave me the password for level two. The `./` tells the terminal that this is a file in the current directory.

### Takeaways  
This level teaches how to handle filenames that the shell might interpret as options and emphasizes using relative paths to access such files safely.

## Level Two  
### Goal  
The password for the next level is stored in a file called `--spaces in this filename--` located in the home directory.

### Process  
To start this one, I knew the file was in the home directory, so I began with:  
`ls -la`

This revealed the file `--spaces in this filename--` as mentioned in the goal. When a file's name starts with a hyphen, the shell interprets it as an option rather than a file. To fix this, I added `--` before the filename to indicate that there were no more options. The command looked like this:  
`cat -- "--spaces in this filename--"`

### Takeaways  
This level teaches how to handle filenames that include spaces or start with special characters, and how to use `--` to prevent the shell from interpreting them as options.

## Level Three  
### Goal  
The password for the next level is stored in a hidden file in the `inhere` directory.

### Process  
Once in, I ran `ls` which revealed the `inhere` directory. Keeping in mind from the prompt that the file is hidden, I used:  
`cd inhere && ls -la`

This revealed the filename `...Hiding-From-You`, which allowed me to get the password with:  
`cat ...Hiding-From-You`

### Takeaways  
This level teaches how to locate hidden files using `ls -la` and reinforces navigating directories to find important files.

## Level Four  
### Goal  
The password for the next level is stored in the only human-readable file in the `inhere` directory. Tip: if your terminal gets messed up, try the `reset` command.

### Process  
This one started out the same as the previous level: I first searched and found the `inhere` directory, then changed into it and searched again. This time, there were 10 different files, with only one being human-readable. To save time and avoid checking each file individually, I used:  
`grep -rI "[a-zA-Z0-9]" .`

This searches recursively with `-r` and ignores binary files with `-I`. The regular expression `[a-zA-Z0-9]` matches any lowercase or uppercase letters and numbers. Since the passwords contain no symbols, this revealed that the password was hidden in `-file07`.

### Takeaways  
This level teaches how to search recursively for human-readable content and filter out binary files using `grep`.

## Level Five  
### Goal  
The password for the next level is stored in a file somewhere under the `inhere` directory and has all of the following properties:  
- human-readable  
- 1033 bytes in size  
- not executable  

### Process  
Once again, I started by searching and switching to the `inhere` directory while using `&& ls -la` to immediately list its contents. Within this directory were about 20 subdirectories, each containing various files, some human-readable and some not. To narrow it down, I used the `find` command with options matching the goal specifications:  
`find . -type f -size 1033c`

This searches starting from `.` (the current directory) recursively. The `-type f` specifies regular files, and `-size 1033c` restricts it to files exactly 1033 bytes in size. This revealed the only matching file: `.file2` in the `maybehere07` directory. From there, I could get the password with:  
`cat ./maybehere07/.file2`

### Takeaways  
This level teaches how to use `find` to locate files based on size, type, and human-readable content when searching through multiple directories.

## Level Six  
### Goal  
The password for the next level is stored somewhere on the server and has all of the following properties:  
- owned by user `bandit7`  
- owned by group `bandit6`  
- 33 bytes in size  

### Process  
For this one, I knew the file was somewhere on the server, so I needed to make my `find` search broader than usual. I ran:  
`find / -type f -size 33c -user bandit7 2>/dev/null`

This searches all directories on the server with the given specifications. `-type f` restricts to files, `-size 33c` to files of 33 bytes, and `-user bandit7` specifies ownership. To avoid "Permission Denied" messages cluttering the output, I added `2>/dev/null`, which suppresses error messages. This revealed a single file matching the description. From there, I got the password with:  
`cat /var/lib/dpkg/info/bandit7.password`

### Takeaways  
This level teaches how to use `find` to locate files anywhere on the server based on ownership, size, and suppressing permission errors.

## Level Seven  
### Goal  
The password for the next level is stored in the file `data.txt` next to the word "millionth".

### Process  
As soon as I accessed this level, a simple `ls` revealed `data.txt`. To find the password, I used:  
`strings data.txt | grep "millionth"`

This extracts all printable strings from `data.txt`, and the piped `grep` filters the output to only show lines containing the word "millionth". This revealed the password for the next level.

### Takeaways  
This level teaches how to extract readable text from a file using `strings` and filter it using `grep` to locate specific content.

## Level Eight  
### Goal  
The password for the next level is stored in the file `data.txt` and is the only line of text that occurs just once.

### Process  
For this one, I needed to search the `data.txt` file in the main directory. I used:  
`strings data.txt | sort | uniq -u`

`strings` extracts printable text from the file, while `sort` arranges the lines so that `uniq -u` can filter out only the unique lines that do not repeat. The `uniq` command only works on consecutive identical lines, so sorting first ensures that all duplicates are grouped together and the unique line can be identified.

### Takeaways  
This level teaches how to identify unique lines in a file by combining `strings`, `sort`, and `uniq -u`.

## Level Nine  
### Goal  
The password for the next level is stored in the file `data.txt` in one of the few human-readable strings, preceded by several `=` characters.

### Process  
This one was similar to the previous level. I needed to search the `data.txt` file in the `bandit9` home directory, but only for lines containing multiple `=` characters. I used:  
`strings data.txt | grep "=="`

This revealed four lines in total, one of which contained the password.

### Takeaways  
This level teaches how to search for specific patterns in a file using `grep` in combination with `strings` to extract human-readable content.

## Level Ten  
### Goal  
The password for the next level is stored in the file `data.txt`, which contains Base64-encoded data.

### Process  
There was a `data.txt` file in the starting directory. Since the file contains the password encoded in Base64, I used:  
`cat data.txt | base64 -d`

This reads the file and pipes the contents into the `base64` command with the `-d` flag, which decodes the Base64 data, revealing the password.

### Takeaways  
This level teaches how to decode Base64-encoded content using the `base64 -d` command.

## Level Eleven  
### Goal  
The password for the next level is stored in the file `data.txt`, where all lowercase (a-z) and uppercase (A-Z) letters have been rotated by 13 positions (ROT13).

### Process  
I recognized that the file was encoded with ROT13, so I used `cat` on the file to view the text. I then used CyberChef, applied ROT13, and obtained the password. Alternatively, this can be done directly in the terminal using `tr`:  
`cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'`

The `tr` command translates or deletes characters. For ROT13, the first set (`A-Za-z`) specifies the characters to replace, and the second set (`N-ZA-Mn-za-m`) specifies the characters to map them to, starting 13 letters forward. Both methods reveal the password for level twelve.

### Takeaways  
This level teaches how to decode ROT13-encoded text using either CyberChef or the `tr` command in the terminal.

## Level Twelve  
### Goal  
The password for the next level is stored in the file `data.txt`, which is a hexdump of a file that has been repeatedly compressed. For this level, it’s useful to create a working directory under `/tmp`. You can use `mkdir` with a hard-to-guess name or, better, `mktemp -d`. Then copy the data file using `cp` and rename it with `mv`.

### Process  
To start, I created a temporary directory and copied the main file there before moving into it:  
```bash
ls
mktemp -d
cp data.txt /tmp/tmp.hFF0B5vm0r
cd /tmp/tmp.hFF0B5vm0r
```

Next, I reversed the hexdump and checked the file type:  
```bash
xxd -r data.txt > hex.dump
file hex.dump
```

The `hex.dump` file was a gzip file, so I started decompressing layers, moving between gzip and bzip2:  
```bash
mv hex.dump file.gz
gunzip file.gz
file file
mv file file.bz
bunzip2 file.bz
file file
```

The file returned to gzip format, which I decompressed into a tar archive:  
```bash
mv file file.gz
gunzip file.gz
file file
mv file file.tar
tar -xvf file.tar
file data5.bin
```

`data5.bin` was another tar archive, so I decompressed it:  
```bash
mv data5.bin data5.tar
tar -xvf data5.tar
```

This produced `data6.bin`, a bzip2 file. I converted and decompressed it, producing another tar archive:  
```bash
file data6.bin
mv data6.bin data6.bz
bunzip2 data6.bz
ls -l
file data6
mv data6 data.tar
tar -xvf data6.tar
```

Finally, `data8.bin` was a gzip file. I converted and decompressed it one last time:  
```bash
file data8.bin
mv data8.bin data8.gz
gunzip data8.gz
ls -l
cat data8
```

Using `cat` on `data8` revealed the password for the next level.

### Takeaways
This level teaches how to reverse a hexdump, identify file types, and handle multiple layers of compression and archives to extract hidden data.

## Level Thirteen  
### Goal
The password for the next level is stored in /etc/bandit_pass/bandit14 and can only be read by user bandit14. For this level, you don’t get the next password directly, but you get a private SSH key that can be used to log into the next level. Look at the commands that logged you into previous Bandit levels and figure out how to use the key for this level.

### Process
The first thing I did once logged in was search and noticed the "sshkey.private" file, which I needed to move to my own system in order to use. To do so, I exited the SSH session and used the scp command to copy the file to my own system with this command:  
`scp -P 2220 bandit13@bandit.labs.overthewire.org:~/sshkey.private .`

Once I had the RSA key on my system, I needed to ensure I could use it. This was as simple as using this command:  
`chmod 600 sshkey.private`

After this, I just needed to specify that I wanted to use the newfound file during my SSH attempt, rather than a password. I did this by appending `-i` to the ssh command and specifying the RSA file. It looked like this:  
`ssh -i sshkey.private bandit14@bandit.labs.overthewire.org -p 2220`

Once in the system again as bandit14, I then needed to move to the directory /etc/bandit_pass and read the bandit14 file for this level's password.

### Takeaways  
This level teaches how to use a private SSH key for authentication and how to securely copy and set permissions for key files with `scp` and `chmod`.

## Level Fourteen  
### Goal
The password for the next level can be retrieved by submitting the password of the current level to port 30000 on localhost.

### Process
This one was simple. All I had to do was input my password into localhost on port 30000. To do that, I used nc with this command:  
`nc localhost 30000`

Once connected, I was given a blank line to type on, where I entered the previous level's password. It then output level fifteen's password.

### Takeaways  
This level teaches how to interact with a service running on a local port using `nc` (netcat) and submit input to retrieve data.

## Level Fifteen  
### Goal
The password for the next level can be retrieved by submitting the password of the current level to port 30001 on localhost using SSL/TLS encryption.  
Helpful note: Getting “DONE”, “RENEGOTIATING” or “KEYUPDATE”? Read the “CONNECTED COMMANDS” section in the manpage.

### Process
The goal specifies that I need to do the same thing as the previous task, but this time through SSL/TLS encryption. Knowing this, I knew I would want to use openssl. I also checked the manual page for s_client, which confirmed openssl was the right tool for full documentation. Once ready, it was as simple as entering:  
`openssl s_client -connect localhost:30001`

After running this, there was a moment while the connection was established before I was given a blank line to begin entering text. From here, I simply entered my previous password, and the new password was output.

### Takeaways  
This level teaches how to use `openssl s_client` to connect to a local SSL/TLS service and submit input securely.

## Level Sixteen  
### Goal  
The credentials for the next level can be retrieved by submitting the password of the current level to a port on localhost in the range 31000 to 32000. First, find out which of these ports have a server listening on them. Then find out which of those speak SSL/TLS and which do not. There is only one server that will give the next credentials; the others will simply send back whatever you send to them.

### Process  
The first step was to figure out which ports in general were open within the range, and doing a full port scan on all of those ports individually would have taken too long. The command for this was simple:  
`nmap localhost -p31000-32000`

This provided me with a list of five open ports. From there, I needed to figure out which of those ports were using SSL/TLS as a service. There were two; one was designed to echo back what I sent, while the other had an unknown service running on it. The command for this was:  
`nmap -sV localhost -p31046,31518,31691,31790,31960`

Once I knew which port to use, I needed to initiate a connection to it over localhost while blocking out interactive commands and treating my input as application data. The command for this looked like:  
`openssl s_client -connect localhost:31790 -quiet`

Once I was connected, I simply input the password for this level and was given an RSA private key as the output.

### Takeaways  
This level teaches how to scan a range of ports with `nmap`, identify SSL/TLS services, and connect to a target port using `openssl s_client` to retrieve sensitive data.

## Level Seventeen  
### Goal  
There are two files in the home directory: passwords.old and passwords.new. The password for the next level is in passwords.new and is the only line that has been changed between passwords.old and passwords.new.

### Process  
This was a simple process using the diff command. To confirm the files, I used `ls`, and then I ran:  
`diff passwords.old passwords.new`

The results showed the line that was removed and the line that was added, which was the password for the next level.

### Takeaways  
This level teaches how to use `diff` to compare files and quickly identify changes between them.

## Level Eighteen  
### Goal  
The password for the next level is stored in a file `readme` in the home directory. Unfortunately, someone has modified `.bashrc` to log you out immediately when you log in with SSH.

### Process  
The first thing I wanted to do was confirm that the directory I would enter had I been allowed in was correct. I started with:  
`ssh bandit18@bandit.labs.overthewire.org -p 2220 pwd`

This confirmed I was in the home directory where the file was located. From here, it was as simple as running:  
`ssh bandit18@bandit.labs.overthewire.org -p 2220 cat readme`

### Takeaways  
This level teaches how to bypass `.bashrc` logout issues by running commands directly over SSH without opening an interactive session.

## Level Nineteen
### Goal
To gain access to the next level, you should use the setuid binary in the home directory. Execute it without arguments to find out how to use it. The password for this level can be found in the usual place (/etc/bandit_pass), after you have used the setuid binary.

### Process
Once entering the system, I ran a simple `ls` to get the setuid binary name, which was "bandit20-do." As the description suggested, I attempted to use the binary with:
`./bandit20-do`

This showed me that I needed to append the commands I wanted to run with it, and in doing so, they would execute with the privileges of the file owner. I started with:
`./bandit20-do ls /etc/bandit_pass`

This confirmed multiple password files within the directory, including bandit20. From there, it was as simple as using the same structure as before, but this time to read the file:
`./bandit20-do cat /etc/bandit_pass/bandit20`

### Takeaways
This level teaches how setuid binaries can execute commands with elevated privileges and why they must be handled carefully from a security perspective.

## Level Twenty
### Goal
There is a setuid binary in the home directory that does the following: it makes a connection to localhost on the port you specify as a command line argument. It then reads a line of text from the connection and compares it to the password from the previous level (bandit20). If the password is correct, it will transmit the password for the next level (bandit21).

### Process
The first thing I did was log in and run `ls` in the home directory to see what the setuid binary was called. It was "suconnect." The next thing I did was run:
`nano suconnect`

This allowed me to view some of the text inside the binary to get a better idea of how it works.

From here, I needed to create a listener on an unused port. To do this, I used:
`nc -l 5555`

This created a listener on port 5555. Once this was set up and ready to go, I opened a new SSH session in a separate terminal and ran:
`./suconnect 5555`

After that, I entered the previous level's password into the netcat listener, and the next level's password was sent back through the connection.

### Takeaways
This level teaches how setuid binaries can interact with network sockets and reinforces how client and listener connections work locally through netcat.
