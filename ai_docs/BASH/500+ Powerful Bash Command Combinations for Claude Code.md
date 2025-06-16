# 500+ Powerful Bash Command Combinations for Claude Code
*Compiled on May 25, 2025*
## Introduction
This document contains a comprehensive collection of 500+ powerful bash command combinations, pipelines, and one-liners specifically curated for use with Claude Code. These examples demonstrate the versatility and power of bash programming for various tasks including:
- Text processing and manipulation- File operations and management- Data processing and analysis- System administration and monitoring- Network operations and diagnostics- Process management and optimization- Security operations and hardening- Performance optimization techniques- Advanced scripting patterns
Each example includes the command itself and a concise explanation of what it does. The examples range from practical everyday commands to advanced multi-step pipelines that solve complex problems.
## How to Use This Document
The examples are organized by category, with the most numerous categories appearing first. Within each category, examples are presented in order of increasing complexity. You can:
1. Browse by category to find commands relevant to your specific needs2. Use the table of contents to jump to sections of interest3. Copy and adapt these commands for your own scripts and workflows4. Study the patterns to improve your bash programming skills
> **Note**: Always review and understand commands before executing them, especially those that modify files or system settings.
## Table of Contents
1. [One Liners](#one_liners) (147 examples)
2. [File Operations](#file_operations) (86 examples)
3. [Text Processing](#text_processing) (54 examples)
4. [Data Processing](#data_processing) (36 examples)
5. [Networking](#networking) (35 examples)
6. [Scripting Techniques](#scripting_techniques) (34 examples)
7. [Process Management](#process_management) (31 examples)
8. [System Administration](#system_administration) (30 examples)
9. [Performance Optimization](#performance_optimization) (30 examples)
10. [Security](#security) (27 examples)
## One Liners <a name="one_liners"></a>
Powerful single-line commands that combine multiple operations to accomplish complex tasks efficiently.
### 1. Check last exit code
```bash
echo $?
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 2. Delete/remove last line
```bash
sed '$d'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 3. Add newline to the end
```bash
sed '$a\'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 4. Regex any single character (e.g. ACB or AEB)
```bash
grep 'A.B'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 5. Set tab as delimiter (default:space)
```bash
xargs -d\t
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 6. switch (case in bash)
```bash
read type;
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 7. Remove only leading whitespace
```bash
sed 's/ *//'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 8. Set tab as field separator
```bash
awk -F $'\t'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 9. Turn output into a single line
```bash
ls -l| xargs
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 10. Echo a random number
```bash
echo $RANDOM
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 11. Show IP address
```bash
$ip add show
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 12. Print every odd # lines
```bash
sed -n '1~2p'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 13. Remove ending commas
```bash
sed 's/,$//g'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 14. Print command along with output: bin/echo abcd
```bash
xargs -t abcd
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 15. Delete/remove empty lines
```bash
sed '/^\s*$/d'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 16. Regex with or without a certain character (e.g. color or colour)
```bash
grep 'colou\?r'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 17. Remove the 1st line
```bash
sed 1d filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 18. Select lines start with string (e.g. 'bbo')
```bash
sed -n '/^@S/p'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 19. Add a column to the end: $i is the valuable you want to add
```bash
sed "s/$/\t$i/"
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 20. Change delimiter
```bash
sed 's=/=\\/=g'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 21. Output as tab separated (also as field separator)
```bash
awk -v OFS='\t'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 22. Reverse string
```bash
echo 12345| rev
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 23. Generate all combination (e.g. 1,2): 1 1, 1 2, 2 1, 2 2
```bash
echo {1,2}{1,2}
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 24. Generate all combination (e.g. A,T,C,G)
```bash
set = {A,T,C,G}
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 25. Print every third line including the first line
```bash
sed -n '1p;0~3p'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 26. Print a particular line (e.g. 123th line)
```bash
sed -n -e '123p'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 27. Find number of columns
```bash
awk '{print NF}'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 28. Encode strings as Base64 strings: dGVzdAo=
```bash
echo test|base64
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 29. Remove the first 100 lines (remove line 1-100)
```bash
sed 1,100d filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 30. Print field start with string (e.g Linux)
```bash
awk '$1 ~ /^Linux/'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 31. Show limits on command-line length: Output from my Ubuntu:
```bash
xargs --show-limits
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 32. Show the 20 most recently modified files/directories
```bash
ls -lt | head -n 20
```
### 33. Sum up input list (e.g. seq 10)
```bash
seq 10|paste -sd+|bc
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 34. Add \n every nth character (e.g. every 4th character)
```bash
sed 's/.\{4\}/&\n/g'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 35. Remove leading whitespace and tabs: Notice a whitespace before '\t'!!
```bash
sed -e 's/^[ \t]*//'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 36. Reverse column order
```bash
awk '{print $2, $1}'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 37. Check if there is a comma in a column (e.g. column $1)
```bash
awk '$1~/,/ {print}'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 38. Prompt commands before running commands
```bash
ls|xargs -L1 -p head
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 39. Remove lines with string (e.g. 'bbo'): case insensitive:
```bash
sed "/bbo/d" filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 40. Remove lines whose nth character not equal to a value (e.g. 5th character not equal to 2): aaaa2aaa (you can stay)
```bash
sed -E '/^.{5}[^2]/d'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 41. Delete lines with string (e.g. 'bbo')
```bash
sed '/bbo/d' filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 42. Remove lines with string (e.g. 'bbo')
```bash
awk '!/bbo/' filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 43. Random from 0-9
```bash
echo $((RANDOM % 10))
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 44. Replace newline
```bash
tr '\n' ' ' <filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 45. Squeeze repeat patterns (e.g. /t/t --> /t)
```bash
tr -s "/t" < filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 46. Substitution (e.g. replace A by B)
```bash
sed 's/A/B/g' filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 47. Print every nth lines
```bash
sed -n '0~3p' filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 48. Arithmetic Expansion in Bash (Operators: +, -, *, /, %, etc)
```bash
echo $(( 10 + 5 ))  #15
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 49. Remove newline\ nextline
```bash
sed ':a;N;$!ba;s/\n//g'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 50. Random from 1-10
```bash
echo $(((RANDOM %10)+1))
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 51. COLOR the match (e.g. 'bbo')!
```bash
grep --color bbo filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 52. Print/get/trim a range of line (e.g. line 500-5000)
```bash
sed -n 500,5000p filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 53. Print a number of lines (e.g. line 10th to line 33 rd)
```bash
sed -n '10,33p' <filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 54. Prompt before execution
```bash
echo a b c |xargs -p -n 3
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 55. Count the number of Segate hard disks: or
```bash
lsscsi|grep SEAGATE|wc -l
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 56. Add string to beginning of every line (e.g. 'bbo')
```bash
sed -e 's/^/bbo/' filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 57. Replace with wildcard (e.g A-1-e or A-2-e or A-3-e....)
```bash
sed 's/A-.*-e//g' filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 58. Remove last column
```bash
awk 'NF{NF-=1};1' filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 59. Check if it's root running
```bash
if [ "$EUID" -ne 0 ]; then
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 60. Check if it's root
```bash
if [ $(id -u) -ne 0 ];then
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 61. Translate a range of characters (e.g. substitute a-z into a): aaaaaaaaa
```bash
echo 'something' |tr a-z a
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 62. Run command only if another command returns zero exit status (well done)
```bash
cd tmp/ && tar xvf ~/a.tar
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 63. Count occurrence (e.g. three times a line count three times)
```bash
grep -o bbo filename |wc -l
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 64. Add string to end of each line (e.g. "}")
```bash
sed -e 's/$/\}\]/' filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 65. Display 3 items per line: 1 2 3
```bash
echo 1 2 3 4 5 6| xargs -n 3
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 66. Cut the last column
```bash
cat filename|rev|cut -f1|rev
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 67. Print commands and their arguments when execute (e.g. echo `expr 10 + 20 `): or
```bash
set -x; echo `expr 10 + 20 `
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 68. Show size of log files and directories, sorted by size
```bash
du -sh /var/log/* | sort -hr
```
### 69. Scan for open ports and OS and version detection (e.g. scan the domain "scanme.nmap.org"): -A to enable OS and version detection, script scanning, and traceroute; -T4 for faster execution
```bash
$ nmap -A -T4 scanme.nmap.org
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 70. Delete all non-printing characters
```bash
tr -dc '[:print:]' < filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 71. Add a line after the line that matches the pattern (e.g. add a new line with "world" after the line with "hello"): hello
```bash
sed '/hello*/a world' filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 72. With find and rm
```bash
find . -name "*.html"|xargs rm
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 73. wait for random duration (e.g. sleep 1-5 second, like adding a jitter)
```bash
sleep $[ ( $RANDOM % 5 ) + 1 ]
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 74. Right align a column (right align the 2nd column)
```bash
cat file.txt|rev|column -t|rev
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 75. Show only directories that are using gigabytes of space
```bash
du -sh * | grep -E "^[0-9.]+G"
```
### 76. Add string to the beginning of a column (e.g add "chr" to column $3)
```bash
awk 'BEGIN{OFS="\t"}$3="chr"$3'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 77. Follow the most recent logs from service
```bash
journalctl -u <service_name> -f
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 78. List directories sorted by size
```bash
ls -la | grep ^d | sort -nk 5,5
```
### 79. Give number/index to every row
```bash
awk '{printf("%s\t%s\n",NR,$0)}'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 80. Export PATH
```bash
export PATH=$PATH:~/path/you/want
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 81. Repeat printing string n times (e.g. print 'hello world' five times)
```bash
printf 'hello world\n%.0s' {1..5}
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 82. Do not echo the trailing newline
```bash
username=`echo -n "bashoneliner"`
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 83. Run command only if another command returns non-zero exit status (not finish)
```bash
cd tmp/a/b/c ||mkdir -p tmp/a/b/c
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 84. Find all TODO comments in Python files recursively
```bash
grep -r "TODO" --include="*.py" .
```
### 85. Find all TODO comments in Python files recursively
```bash
grep -r "TODO" --include="*.py" .
```
### 86. Locate and remove a package
```bash
sudo dpkg -l | grep <package_name>
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 87. Show the top 5 CPU-consuming processes
```bash
ps aux | sort -nrk 3,3 | head -n 5
```
### 88. Show the top 5 CPU-consuming processes
```bash
ps aux | sort -nrk 3,3 | head -n 5
```
### 89. Copy your default public key to remote user: then you need to enter the password
```bash
ssh-copy-id <user_name>@<server_IP>
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 90. Substitution with wildcard (e.g. replace a line start with aaa= by aaa=/my/new/path)
```bash
sed "s/aaa=.*/aaa=\/my\/new\/path/g"
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 91. To both view and store the output: use '-a' with tee to append to file.
```bash
echo 'hihihihi' | tee outputfile.txt
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 92. Add string at certain line number (e.g. add 'something' to line 1 and line 3)
```bash
sed -e '1isomething' -e '3isomething'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 93. Print line number and number of characters on each line
```bash
awk '{print NR,length($0);}' filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 94. List all enabled services
```bash
systemctl list-unit-files|grep enabled
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 95. Wrap each input line to fit in specified width (e.g 4 integers per line): 0011
```bash
echo "00110010101110001101" | fold -w4
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 96. Parallel
```bash
time echo {1..5} |xargs -n 1 -P 5 sleep
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 97. Remove newline / nextline
```bash
tr --delete '\n' <input.txt >output.txt
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 98. Print all lines before nth occurrence of a string (e.g stop print lines when 'bbo' appears 7 times)
```bash
awk -v N=7 '{print}/bbo/&& --N<=0 {exit}'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 99. Get all username
```bash
getent passwd| awk '{FS="[:]"; print $1}'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 100. Convert the hexadecimal MD5 checksum value into its base64-encoded format.: NWbeOpeQbtuY0ATWuUeumw==
```bash
openssl md5 -binary /path/to/file| base64
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 101. Show directories using gigabytes of space, sorted by size
```bash
du -sh * | grep -E "^[0-9.]+G" | sort -hr
```
### 102. Subtract previous row values (add column6 which equal to column4 minus last column5)
```bash
awk '{$6 = $4 - prev5; prev5 = $5; print;}'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 103. Random order (lucky draw)
```bash
for i in a b c d e; do echo $i; done | shuf
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 104. Generate public key from private key
```bash
ssh-keygen -y -f ~/.ssh/id_rsa > ~/.ssh/id_rsa.pub
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 105. Press any key to continue
```bash
read -rsp $'Press any key to continue...\n' -n1 key
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 106. Count lines in all Python files and sort by line count
```bash
find . -type f -name "*.py" | xargs wc -l | sort -nr
```
### 107. Reverse the result from `uniq -c`
```bash
while read a b; do yes $b |head -n $a ; done <test.txt
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 108. Find the 20 largest files in the current directory and subdirectories
```bash
find . -type f -exec du -sh {} \; | sort -hr | head -n 20
```
### 109. Find the 20 largest files in the current directory and subdirectories
```bash
find . -type f -exec du -sh {} \; | sort -hr | head -n 20
```
### 110. Show top 10 processes using more than 0.5% of memory
```bash
ps aux | awk '{if($4>0.5)print $0}' | sort -nrk 4 | head -n 10
```
### 111. Column subtraction
```bash
cat file| awk -F '\t' 'BEGIN {SUM=0}{SUM+=$3-$2}END{print SUM}'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 112. Split and do for loop
```bash
awk '{split($2, a,",");for (i in a) print $1"\t"a[i]}' filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 113. Find out the time spent between request and response
```bash
curl -v -o /dev/null -s -w 'Total: %{time_total}s\n' google.com
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 114. Set beep duration
```bash
(speaker-test -t sine -f 1000) & pid=$!;sleep 0.1s;kill -9 $pid
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 115. Find all unique import statements in Python files
```bash
grep -r --include="*.py" "import" . | cut -d: -f2 | sort | uniq
```
### 116. Unshorten a shortended URL
```bash
curl -s -o /dev/null -w "%{redirect_url}" https://bit.ly/34EFwWC
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 117. Make all directories at one time!: -p: make parent directory
```bash
mkdir -p project/{lib/ext,bin,src,doc/{html,info,pdf},demo/stat}
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 118. List files in the current directory and show sizes in MB for files larger than 1MB
```bash
ls -la | awk '{if ($5 > 1024*1024) print $5/1024/1024 "MB " $9}'
```
### 119. List files in the current directory and show sizes in MB for files larger than 1MB
```bash
ls -la | awk '{if ($5 > 1024*1024) print $5/1024/1024 "MB " $9}'
```
### 120. Show the top 10 most frequently used commands from your bash history
```bash
history | awk '{print $2}' | sort | uniq -c | sort -rn | head -10
```
### 121. Show the top 10 most frequently used commands from your bash history
```bash
history | awk '{print $2}' | sort | uniq -c | sort -rn | head -10
```
### 122. Find and remove all backup and temporary files
```bash
find . -name "*.bak" -o -name "*.tmp" -o -name "*.backup" | xargs rm
```
### 123. Create a UEFI Bootable USB drive (e.g. /dev/sdc1)
```bash
sudo dd if=~/path/to/isofile.iso of=/dev/sdc1 oflag=direct bs=1048576
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 124. List all GitHub repositories for a user using the GitHub API
```bash
curl -s https://api.github.com/users/username/repos | jq -r '.[].name'
```
### 125. List details of log files containing ERROR messages
```bash
find . -type f -name "*.log" -exec grep -l "ERROR" {} \; | xargs ls -lh
```
### 126. Count lines in all text files containing a specific pattern
```bash
find . -type f -name "*.txt" -exec grep -l "pattern" {} \; | xargs wc -l
```
### 127. Archive all log files modified in the last 7 days
```bash
find . -type f -mtime -7 -name "*.log" | xargs tar -czf recent_logs.tar.gz
```
### 128. Find all JPG files created in the year 2023
```bash
find . -type f -name "*.jpg" -newermt "2023-01-01" ! -newermt "2023-12-31"
```
### 129. Find and kill all Firefox processes
```bash
ps aux | grep -v grep | grep -i "firefox" | awk '{print $2}' | xargs kill -9
```
### 130. Count lines in log files containing ERROR messages and sort by line count
```bash
find . -type f -name "*.log" -exec grep -l "ERROR" {} \; | xargs wc -l | sort -nr
```
### 131. List all JPG images sorted by resolution (width)
```bash
find . -type f -name "*.jpg" -exec identify -format "%f %wx%h\n" {} \; | sort -nrk 3
```
### 132. Send mail: use -a flag to set send from (-a "From: some@mail.tld")
```bash
echo 'heres the content'| mail -a /path/to/attach_file.txt -s 'mail.subject' me@gmail.com
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 133. Count established network connections by IP address
```bash
netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr
```
### 134. Find Java files creating threads and sort by frequency
```bash
grep -r --include="*.java" "new Thread" . | awk -F: '{print $1}' | sort | uniq -c | sort -nr
```
### 135. Show the 5 most recent log files containing OutOfMemoryError
```bash
find . -type f -name "*.log" -exec grep -l "OutOfMemoryError" {} \; | xargs ls -ltr | tail -n 5
```
### 136. Count failed SSH login attempts by username
```bash
cat /var/log/auth.log | grep -i "failed password" | awk '{print $11}' | sort | uniq -c | sort -nr
```
### 137. Find configuration files with DEBUG enabled and disable it
```bash
find . -type f -name "*.conf" -exec grep -l "DEBUG" {} \; | xargs sed -i 's/DEBUG=true/DEBUG=false/g'
```
### 138. Show top 10 IP addresses with the most established connections
```bash
netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -n 10
```
### 139. List directories using gigabytes of space with formatted output saved to file
```bash
du -sh * | grep -E "^[0-9.]+G" | sort -hr | awk '{printf "%-8s %s\n", $1, $2}' | tee large_directories.txt
```
### 140. Archive log files from the last 7 days containing exceptions
```bash
find . -type f -mtime -7 -name "*.log" | xargs grep -l "Exception" | xargs tar -czf recent_exceptions.tar.gz
```
### 141. Sort a row (e.g. 1 40  35  12  23  --> 1 12    23  35  40)
```bash
awk ' {split( $0, a, "\t" ); asort( a ); for( i = 1; i <= length(a); i++ ) printf( "%s\t", a[i] ); printf( "\n" ); }'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 142. Download the content of this README.md (the one your are viewing now)
```bash
curl https://raw.githubusercontent.com/onceupon/Bash-Oneliner/master/README.md | pandoc -f markdown -t man | man -l -
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 143. Show top 5 memory-consuming processes using more than 1% of memory with formatted output
```bash
ps aux | awk '{if($4>1.0)print $0}' | sort -nrk 4 | head -n 5 | awk '{printf "%-10s %-5s %-5s %-10s\n", $1, $2, $4, $11}'
```
### 144. Count and sort Python import statements by frequency across all files
```bash
find . -type f -name "*.py" -exec grep -l "import" {} \; | xargs cat | grep -E "^import|^from" | sort | uniq -c | sort -nr
```
### 145. Find top 20 most frequently used Python imports across all files
```bash
find . -type f -name "*.py" -exec grep -l "import" {} \; | xargs cat | grep -E "^import|^from" | sort | uniq -c | sort -nr | head -n 20
```
### 146. Find top 10 error-containing log files by line count with formatted output
```bash
find . -type f -name "*.log" -exec grep -l "ERROR" {} \; | xargs wc -l | sort -nr | head -n 10 | awk '{printf "%-8s %s\n", $1, $2}' > top_error_logs.txt
```
### 147. Archive log files from the last 7 days containing exceptions and report count
```bash
find . -type f -mtime -7 -name "*.log" | xargs grep -l "Exception" | tar -czf recent_exceptions.tar.gz -T - && echo "Archived $(tar -tzf recent_exceptions.tar.gz | wc -l) log files with exceptions"
```
## File Operations <a name="file_operations"></a>
Commands for finding, manipulating, organizing, and transforming files and directories.
### 1. List all sub directory/file in the current directory
```bash
find .
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 2. Get last history/record filename
```bash
head !$
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 3. Create or replace a file with contents
```bash
cat >myfile
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 4. Append to a file with contents
```bash
cat >>myfile
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 5. Get parent directory of current directory
```bash
dirname `pwd`
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 6. Remove last character of file
```bash
sed '$ s/.$//'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 7. Count lines in all file, also count total lines
```bash
ls|xargs wc -l
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 8. List all files under the current directory
```bash
find . -type f
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 9. List all directories under the current directory
```bash
find . -type d
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 10. Create a temporary directory and `cd` into it: for example, this will create a temporary directory "/tmp/tmp.TivmPLUXFT"
```bash
cd $(mktemp -d)
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 11. Compare two files (e.g. fileA, fileB): a: added; d:delete; c:changed
```bash
diff fileA fileB
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 12. Add file extension to all file(e.g add .txt): You can use rename -n s/$/.txt/ * to check the result first, it will only print sth like this:
```bash
rename s/$/.txt/ *
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 13. Grep all content of a fileA from fileB
```bash
grep -f fileA fileB
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 14. Count all files
```bash
ls |xargs -n1 wc -l
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 15. Describe the format and characteristics of image files: myimage.png PNG 1049x747 1049x747+0+0 8-bit sRGB 1.006MB 0.000u 0:00.000
```bash
identify myimage.png
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 16. List directories in the current path sorted by size
```bash
du -sh */ | sort -hr
```
### 17. Find empty (0 byte) files: to further delete all the empty files
```bash
find . -type f -empty
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 18. Add string to end of file (e.g. "]")
```bash
sed '$s/$/]/' filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 19. Recursively count all the files in a directory
```bash
find . -type f | wc -l
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 20. Append to file (e.g. hihi)
```bash
echo 'hihi' >>filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 21. Run command in background, output error file
```bash
some_commands  &>log &
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 22. Edit infile (edit and save to file), (e.g. deleting the lines with 'bbo' and save to file)
```bash
sed -i "/bbo/d" filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 23. Find large files in the system (e.g. >4G)
```bash
find / -type f -size +4G
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 24. Add string to beginning of file (e.g. "\[")
```bash
sed -i '1s/^/[/' filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 25. Delete/remove last character from end of file
```bash
sed -i '$ s/.$//' filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 26. Average a file (each line in file contains only one number)
```bash
awk '{s+=$1}END{print s/NR}'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 27. Grep search all files in a directory(e.g. 'bbo'): or
```bash
grep -R bbo /path/to/directory
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 28. Concatenate/combine/join files with a separator and next line (e.g separate by ",")
```bash
sed -s '$a,' *.json > all.json
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 29. Search all files in directory, do not ouput the filenames (e.g. 'bbo')
```bash
grep -rh bbo /path/to/directory
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 30. Search all files in directory, output ONLY the filenames with matches(e.g. 'bbo')
```bash
grep -rl bbo /path/to/directory
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 31. Insert character at specified position of file (e.g. AAAAAA --> AAA#AAA)
```bash
sed -r -e 's/^.{3}/&#/' filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 32. Stop tailing a file on program terminate: replace <PID> with the process ID of the program.
```bash
tail -f --pid=<PID> filename.txt
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 33. Cut and get last column of a file
```bash
cat file|rev | cut -d/ -f1 | rev
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 34. Move first 100th files to a directory (e.g. d1)
```bash
ls |head -100|xargs -I {} mv {} d1
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 35. Find and output only filename (e.g. "mso")
```bash
find mso*/ -name M* -printf "%f\n"
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 36. Skip directory (e.g. 'bbo')
```bash
grep -d skip 'bbo' /path/to/files/*
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 37. Sum up a file (each line in file contains only one number)
```bash
awk '{s+=$1} END {print s}' filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 38. Compare two files, strip trailing carriage return/ nextline (e.g. fileA, fileB)
```bash
diff fileA fileB --strip-trailing-cr
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 39. Find and delete file with size less than (e.g. 74 byte)
```bash
find . -name "*.mso" -size -74c -delete
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 40. Copy a file to multiple files (e.g copy fileA to file(B-D))
```bash
tee <fileA fileB fileC fileD >/dev/null
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 41. Round all numbers of file (e.g. 2 significant figure)
```bash
awk '{while (match($0, /[0-9]+\[0-9]+/)){
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 42. Delete files with whitespace in filename (e.g. "hello 2001")
```bash
find . -name "*.c" -print0|xargs -0 rm -rf
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 43. Delete all log files older than 30 days
```bash
find . -type f -name "*.log" -mtime +30 -delete
```
### 44. Find and delete log files older than 30 days
```bash
find . -type f -name "*.log" -mtime +30 -delete
```
### 45. Edit all files under current directory (e.g. replace 'www' with 'ww')
```bash
find . -name '*.php' -exec sed -i 's/www/w/g' {} \;
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 46. Create dummy file of certain size (e.g. 200mb): or
```bash
dd if=/dev/zero of=/dev/shm/200m bs=1024k count=200
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 47. Move files to folder
```bash
find . -name "*.bak" -print 0|xargs -0 -I {} mv {} ~/old
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 48. Find the 10 largest files in the current directory and subdirectories
```bash
find . -type f -exec du -sh {} \; | sort -hr | head -n 10
```
### 49. Create a compressed tar archive and send it to a remote server in one command
```bash
tar -czf - directory | ssh user@host "cat > backup.tar.gz"
```
### 50. Replace 'foo' with 'bar' in all text files recursively
```bash
find . -type f -name "*.txt" -exec sed -i 's/foo/bar/g' {} \;
```
### 51. Print filename and last line of all files in directory
```bash
ls|xargs -n1 -I file awk '{s=$0};END{print FILENAME,s}' filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 52. Add the file name to the first line of file
```bash
ls |sed 's/.txt//g'|xargs -n1 -I file sed -i -e '1 i\>file\' file.txt
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 53. Find log files larger than 100MB and compress them with gzip
```bash
find . -type f -name "*.log" -size +100M -exec bash -c 'gzip "{}"' \;
```
### 54. Find JPG files modified in the last 7 days and copy them to a backup directory
```bash
find . -type f -mtime -7 -name "*.jpg" -exec cp {} /backup/recent/ \;
```
### 55. Find log files larger than 100MB and compress them with gzip
```bash
find . -type f -name "*.log" -size +100M -exec bash -c 'gzip "{}"' \;
```
### 56. Synchronize directories with progress display, excluding temporary files
```bash
rsync -avz --progress --exclude='*.tmp' /source/ user@remote:/destination/
```
### 57. Find all JPG files created in the year 2023
```bash
find . -type f -name "*.jpg" -newermt "2023-01-01" ! -newermt "2023-12-31"
```
### 58. Recursively rename all .txt files to .md files, preserving directory structure
```bash
find . -type f -name "*.txt" -exec bash -c 'mv "$1" "${1%.txt}.md"' _ {} \;
```
### 59. Recursively rename all .txt files to .md files, preserving directory structure
```bash
find . -type f -name "*.txt" -exec bash -c 'mv "$1" "${1%.txt}.md"' _ {} \;
```
### 60. Xargs and sed (replace all old ip address with new ip address under /etc directory)
```bash
grep -rl '192.168.1.111' /etc | xargs sed -i 's/192.168.1.111/192.168.2.111/g'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 61. Convert all Markdown files to PDF using pandoc
```bash
find . -type f -name "*.md" -exec sh -c 'pandoc "$1" -o "${1%.md}.pdf"' _ {} \;
```
### 62. Find and remove all backup and temporary files
```bash
find . -type f -name "*.bak" -o -name "*.tmp" -o -name "*.backup" | xargs rm -f
```
### 63. Resize all JPG images in the current directory and subdirectories to 800x600
```bash
find . -type f -name "*.jpg" -exec bash -c 'convert "{}" -resize 800x600 "{}"' \;
```
### 64. Fastq to fasta (fastq and fasta are common file formats for bioinformatics sequence data)
```bash
cat file.fastq | paste - - - - | sed 's/^@/>/g'| cut -f1-2 | tr '\t' '\n' >file.fa
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 65. Count files within directories: "--" signals the end of options and display further option processing
```bash
echo mso{1..8}|xargs -n1 bash -c 'echo -n "$1:"; ls -la "$1"| grep -w 74 |wc -l' --
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 66. Find average of input list/file of integers
```bash
i=`wc -l filename|cut -d ' ' -f1`; cat filename| echo "scale=2;(`paste -sd+`)/"$i|bc
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 67. List the 10 most recently modified files with timestamps
```bash
find . -type f -exec stat --format '%Y :%y %n' "{}" \; | sort -nr | cut -d: -f2- | head
```
### 68. Resize all JPG images to 50% and optimize quality
```bash
find . -type f -name "*.jpg" -exec bash -c 'convert "{}" -resize 50% -quality 85 "{}"' \;
```
### 69. Add extension of filename to last column
```bash
for i in T000086_1.02.n T000086_1.02.p; do sed "s/$/\t${i/*./}/" $i; done >T000086_1.02.np
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 70. Find Python files with potential issues using pyflakes
```bash
find . -type f -name "*.py" -exec bash -c 'pyflakes "{}" | grep -q . && echo "{}" needs review' \;
```
### 71. Find MP3 files with unknown artist tag
```bash
find . -type f -name "*.mp3" -exec bash -c 'id3info "{}" | grep -q "Artist: Unknown" && echo "{}"' \;
```
### 72. Copy all files from A to B
```bash
find /dir/to/A -type f -name "*.py" -print 0| xargs -0 -r -I file cp -v -p file --target-directory=/path/to/B
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 73. Truncate large log files to last 1000 lines
```bash
find . -type f -name "*.log" -size +100M -exec bash -c 'tail -n 1000 "{}" > "{}.tail" && mv "{}.tail" "{}"' \;
```
### 74. Find encrypted PDF files
```bash
find . -type f -name "*.pdf" -exec bash -c 'pdfinfo "{}" | grep -q "Encrypted: yes" && echo "{}" is encrypted' \;
```
### 75. Convert text files from ISO-8859-1 to UTF-8 encoding
```bash
find . -type f -name "*.txt" -exec bash -c 'iconv -f ISO-8859-1 -t UTF-8 "{}" > "{}.utf8" && mv "{}.utf8" "{}"' \;
```
### 76. Create a backup directory for each directory containing Python files and copy the files there
```bash
find . -type f -name "*.py" -exec bash -c 'mkdir -p "$(dirname "{}")/backup"; cp "{}" "$(dirname "{}")/backup/"' \;
```
### 77. Create a backup directory for each directory containing Python files and copy the files there
```bash
find . -type f -name "*.py" -exec bash -c 'mkdir -p "$(dirname "{}")/backup"; cp "{}" "$(dirname "{}")/backup/"' \;
```
### 78. Compress log files with maximum compression and move to archive directory
```bash
find . -type f -name "*.log" -exec bash -c 'gzip -9 "{}" && mv "{}.gz" "$(dirname {})/archive/$(basename {}).gz"' \;
```
### 79. Clean and format HTML files using tidy
```bash
find . -type f -name "*.html" -exec bash -c 'tidy -m -i -w 120 -ashtml "{}" 2>/dev/null || echo "Could not tidy {}"' \;
```
### 80. Sort CSV files by second column while preserving header
```bash
find . -type f -name "*.csv" -exec bash -c 'head -n 1 "{}" > "{}.header" && tail -n +2 "{}" | sort -t, -k2,2 >> "{}.header" && mv "{}.header" "{}"' \;
```
### 81. Sort all CSV files by the second column while preserving the header row
```bash
find . -type f -name "*.csv" -exec bash -c 'header=$(head -n1 {}); tail -n+2 {} | sort -t, -k2,2 | (echo "$header"; cat) > {}.sorted && mv {}.sorted {}' \;
```
### 82. Organize images into directories based on their dimensions
```bash
find . -type f -name "*.jpg" -exec bash -c 'dimensions=$(identify -format "%wx%h" "{}"); mkdir -p "by-size/$dimensions"; cp "{}" "by-size/$dimensions/"' \;
```
### 83. Find PDF files with more than 10 pages and display their page count
```bash
find . -type f -name "*.pdf" -exec bash -c 'pages=$(pdfinfo "{}" | grep Pages | awk "{print \$2}"); if [ "$pages" -gt 10 ]; then echo "{}" has "$pages" pages; fi' \;
```
### 84. Find JPG files from 2023 and organize into folders by month
```bash
find . -type f -name "*.jpg" -newermt "2023-01-01" ! -newermt "2023-12-31" -exec bash -c 'mkdir -p "2023/$(date -r "{}" +%m)" && cp "{}" "2023/$(date -r "{}" +%m)/"' \;
```
### 85. Archive log files into year-month subdirectories based on their modification time
```bash
find . -type f -name "*.log" -exec bash -c 'logname=$(basename {}); dir=$(dirname {}); mkdir -p "$dir/archive/$(date -r "{}" +%Y-%m)"; gzip -c "{}" > "$dir/archive/$(date -r "{}" +%Y-%m)/$logname.gz"' \;
```
### 86. Organize MP3 files into directories by artist tag, with Unknown for missing tags
```bash
find . -type f -name "*.mp3" -exec bash -c 'artist=$(ffprobe -loglevel error -show_entries format_tags=artist -of default=noprint_wrappers=1:nokey=1 "{}"); mkdir -p "by-artist/${artist:-Unknown}"; cp "{}" "by-artist/${artist:-Unknown}/"' \;
```
## Text Processing <a name="text_processing"></a>
Commands for searching, extracting, transforming, and analyzing text data from files and streams.
### 1. Grep a tab
```bash
grep $'\t'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 2. Grep AND (e.g. A and B)
```bash
grep 'A.*B'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 3. Grep and count number of empty lines
```bash
grep -c "^$"
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 4. Grep string starting with (e.g. 'S')
```bash
grep -o 'S.*'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 5. Grep and return only integer: or
```bash
grep -o '[0-9]*'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 6. Grep whole word (e.g. 'target')
```bash
grep -w 'target'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 7. Grep integer with certain number of digits (e.g. 3): or
```bash
grep '[0-9]\{3\}'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 8. Grep OR (e.g. A or B or C or D)
```bash
grep 'A\|B\|C\|D'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 9. Grep lines without word (e.g. 'bbo')
```bash
grep -v bbo filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 10. Grep and return number of matching line(e.g. 'bbo')
```bash
grep -c bbo filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 11. Grep lines not begin with string (e.g. #)
```bash
grep -v '^#' file.txt
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 12. Grep strings between a bracket()
```bash
grep -oP '\(\K[^\)]+'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 13. Grep variables with space within it (e.g. myvar="some strings"): remember to quote the variable!
```bash
grep "$myvar" filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 14. Grep only one/first match (e.g. 'bbo')
```bash
grep -m 1 bbo filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 15. Case insensitive grep (e.g. 'bbo'/'BBO'/'Bbo')
```bash
grep -i "bbo" filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 16. Remove Windows-style carriage returns (CRLF to LF conversion)
```bash
sed -i 's/\r$//' file.txt
```
### 17. Extract text between words (e.g. w1,w2)
```bash
grep -o -P '(?<=w1).*(?=w2)'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 18. Grep number of characters with known strings in between(e.g. AAEL000001-RA): \w word character [0-9a-zA-Z_] \W not word character
```bash
grep -o -w "\w\{10\}\-R\w\{1\}"
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 19. Sort a CSV file by the second column, then by the first column
```bash
sort -t',' -k2,2 -k1,1 file.csv
```
### 20. Print all lines between patterns START and END (inclusive)
```bash
sed -n '/START/,/END/p' file.txt
```
### 21. Replace all whitespace (tabs, multiple spaces) with a single space
```bash
tr -s '[:space:]' ' ' < file.txt
```
### 22. Show lines matching 'pattern' plus 2 lines before and 3 lines after each match
```bash
grep -A 3 -B 2 'pattern' file.txt
```
### 23. Grep variable from variable
```bash
$echo "$long_str"|grep -q "$short_str"
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 24. Capitalize the first letter of every word in a file
```bash
perl -pe 's/\b(\w+)\b/\u$1/g' file.txt
```
### 25. Remove comments and blank lines from a configuration file
```bash
grep -v '^#' config.txt | grep -v '^$'
```
### 26. Xargs and grep
```bash
cat grep_list |xargs -I{} grep {} filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 27. Type of grep
```bash
grep = grep -G # Basic Regular Expression (BRE)
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 28. With sed
```bash
ls |xargs -n1 -I file sed -i '/^Pos/d' filename
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 29. Extract all JSON string values (text between double quotes, handling escaped quotes)
```bash
grep -o -P '(?<=")(?:\\.|[^"])*(?=")' file.json
```
### 30. Extract text between two patterns (inclusive) from a file
```bash
sed -n '/START_PATTERN/,/END_PATTERN/p' file.txt
```
### 31. Extract all href URLs from an HTML file, sort them, and remove duplicates
```bash
grep -oP '(?<=href=")[^"]+' index.html | sort | uniq
```
### 32. Extract text between HTML title tags using Perl-compatible regex lookbehind/lookahead
```bash
grep -o -P '(?<=<title>).*(?=</title>)' webpage.html
```
### 33. Convert text to title case (capitalize first letter of each word)
```bash
perl -pe 's/\b(\w)/\u$1/g' file.txt > title_case.txt
```
### 34. Extract text between BEGIN and END patterns, excluding the patterns themselves
```bash
sed -n '/BEGIN/,/END/p' file.txt | grep -v 'BEGIN\|END'
```
### 35. Grep only IP address: or
```bash
grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 36. Search for pattern with 2 lines before, 3 lines after, with color highlighting in pager
```bash
grep -A 3 -B 2 --color=always 'pattern' file.txt | less -R
```
### 37. Calculate the average of numbers in the first column of a file
```bash
awk '{sum+=$1} END {print "Average: " sum/NR}' numbers.txt
```
### 38. Remove all double quotes from the third field in a CSV file
```bash
awk 'BEGIN{FS=OFS=","} {gsub(/"/, "", $3); print}' data.csv
```
### 39. Format 10-digit numbers as phone numbers with dashes using regex capture groups
```bash
sed -E 's/([0-9]{3})([0-9]{3})([0-9]{4})/\1-\2-\3/g' file.txt
```
### 40. Remove trailing whitespace from all lines in a file
```bash
awk '{gsub(/[[:space:]]+$/,""); print}' file.txt > cleaned.txt
```
### 41. Show the last 50 lines of log files containing ERROR
```bash
find . -name "*.log" -type f | xargs grep -l "ERROR" | xargs tail -n 50
```
### 42. Join two files based on the first field and append matched values
```bash
awk 'NR==FNR{a[$1]=$2;next} $1 in a{print $0,a[$1]}' file1.txt file2.txt
```
### 43. Join two files on first field and print entire line from first file plus second field from second file
```bash
awk 'NR==FNR{a[$1]=$0;next} ($1 in a){print a[$1],$2}' file1.txt file2.txt
```
### 44. Join two files on the first field and print selected fields
```bash
awk 'NR==FNR{a[$1]=$2;next} $1 in a{print $1,a[$1],$2}' file1.txt file2.txt
```
### 45. Search log file for errors with context and colored output in pager
```bash
grep -A 5 -B 5 -E 'error|exception|fail' --color=always logfile.log | less -R
```
### 46. Extract all unique email addresses from a text file
```bash
grep -o -E '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b' file.txt | sort | uniq
```
### 47. Find all text files containing 'pattern' and replace with 'replacement' in all matches
```bash
find . -type f -name "*.txt" -exec grep -l "pattern" {} \; | xargs sed -i 's/pattern/replacement/g'
```
### 48. Extract, count and sort IP addresses by frequency
```bash
grep -o -E '\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b' file.txt | sort | uniq -c | sort -nr
```
### 49. Extract, count and sort email addresses by frequency
```bash
grep -o -E '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b' file.txt | sort | uniq -c | sort -nr
```
### 50. Extract text between square brackets, count occurrences, and format output with aligned columns
```bash
grep -o -P '(?<=\[).*?(?=\])' log.txt | sort | uniq -c | sort -nr | head -n 20 | awk '{printf "%4d %s\n", $1, $2}'
```
### 51. Extract timestamps from log file, count occurrences, and sort chronologically with counts
```bash
cat log.txt | grep -oP '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}' | sort | uniq -c | awk '{print $2, $3, $1}' | sort -k1,1 -k2,2
```
### 52. Extract H1 headings from HTML, strip remaining tags, convert to lowercase, and replace non-alphanumeric characters with hyphens
```bash
grep -o -P '(?<=<h1>).*?(?=</h1>)' webpage.html | sed 's/<[^>]*>//g' | tr '[:upper:]' '[:lower:]' | tr -cs '[:alnum:]' '-' > headings.txt
```
### 53. Extract email addresses, count occurrences of each domain, and show top 10 most common domains
```bash
grep -o -E '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b' emails.txt | awk -F@ '{print $2}' | sort | uniq -c | sort -nr | head -n 10
```
### 54. Process CSV data to remove quotes from third column and add a new category column based on value ranges
```bash
awk 'BEGIN{FS=OFS=","} NR==1{print} NR>1{gsub(/"/,"",$3); if($3>100){$6="High"}else if($3>50){$6="Medium"}else{$6="Low"}; print}' data.csv > categorized.csv
```
## Data Processing <a name="data_processing"></a>
Commands for parsing, transforming, aggregating, and analyzing structured and semi-structured data.
### 1. Check status of a process using PID
```bash
ps -p <PID>
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 2. List processes by top memory usage
```bash
ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 3. Kill all process of a program
```bash
kill -9 $(ps aux | grep 'program_name' | awk '{print $2}')
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 4. Calculate the average of values in the third column of a CSV file
```bash
awk -F, '{sum+=$3} END {print "Average: " sum/NR}' data.csv
```
### 5. Calculate the average of values in the third column of a CSV file
```bash
awk -F, '{sum+=$3} END {print "Average: " sum/NR}' data.csv
```
### 6. Count unique values in the third column of a CSV file, excluding the header
```bash
cat file.csv | awk -F, 'NR>1{print $3}' | sort -n | uniq | wc -l
```
### 7. Extract name and size fields from JSON, output as TSV, and sort by size
```bash
jq -r '.items[] | [.name, .size] | @tsv' data.json | sort -k2 -nr
```
### 8. Convert specific fields from JSON to TSV format
```bash
jq -r '.[] | [.name, .age, .email] | @tsv' people.json > people.tsv
```
### 9. Extract unique combinations of values from columns 2 and 3 in a CSV file
```bash
cat data.csv | cut -d, -f2,3 | sort | uniq > unique_combinations.csv
```
### 10. Find the top 10 IP addresses with the most requests in an access log
```bash
cat access.log | cut -d' ' -f1 | sort | uniq -c | sort -nr | head -n 10
```
### 11. Find the top 10 IP addresses with the most requests in an access log
```bash
cat access.log | cut -d' ' -f1 | sort | uniq -c | sort -nr | head -n 10
```
### 12. Count and sort ERROR occurrences by timestamp in logs
```bash
cat logs.txt | grep ERROR | cut -d' ' -f1,2 | sort | uniq -c | sort -nr
```
### 13. Fetch JSON data and filter for items with 'active' status
```bash
curl -s https://api.example.com/data | jq '.[] | select(.status=="active")'
```
### 14. Sum values in column 2 grouped by column 1 in CSV, then sort by sum in descending order
```bash
awk -F, '{a[$1]+=$2} END{for (i in a) print i, a[i]}' data.csv | sort -k2,2nr
```
### 15. Filter CSV rows where the third column value is greater than 100
```bash
awk 'BEGIN{FS=","; OFS=","} {if ($3 > 100) print $1, $2, $3}' data.csv > filtered.csv
```
### 16. Extract all IP addresses from a file, count and sort them by frequency
```bash
grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' file.txt | sort | uniq -c
```
### 17. Extract all IP addresses from a file, count and sort them by frequency
```bash
grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' file.txt | sort | uniq -c
```
### 18. Calculate average of column 2 grouped by column 1 and sort by average
```bash
awk -F, '{a[$1]+=$2; b[$1]++} END{for (i in a) print i, a[i]/b[i]}' data.csv | sort -k2,2nr
```
### 19. Find top 20 IP addresses in access log excluding Googlebot
```bash
cat access.log | grep -v 'Googlebot' | cut -d' ' -f1 | sort | uniq -c | sort -nr | head -n 20
```
### 20. Find top 10 most requested URLs in web server logs
```bash
cat access.log | grep -o '"GET [^"]*"' | cut -d' ' -f2 | sort | uniq -c | sort -nr | head -n 10
```
### 21. Calculate average value for entries in May 2023 from JSON data
```bash
cat data.json | jq '.[] | select(.timestamp | startswith("2023-05")) | .value' | jq -s 'add/length'
```
### 22. Filter JSON data for active items and convert selected fields to CSV
```bash
jq -r '.items[] | select(.status=="active") | [.id, .name, .value] | @csv' data.json > active_items.csv
```
### 23. Filter JSON data for active items and convert selected fields to CSV
```bash
jq -r '.items[] | select(.status=="active") | [.id, .name, .value] | @csv' data.json > active_items.csv
```
### 24. Extract timestamp and value from JSON, format as date and value, and sort by date
```bash
cat data.json | jq -r '.[] | [.timestamp, .value] | @csv' | awk -F, '{split($1,d,"T"); print d[1],$2}' | sort -k1,1
```
### 25. Aggregate sales data by month from CSV with ISO dates
```bash
cat sales.csv | awk -F, 'NR>1{month=substr($1,6,2); sales[month]+=$2} END{for (m in sales) print m, sales[m]}' | sort -k1,1n
```
### 26. Group JSON data by category with total price and count
```bash
cat data.json | jq 'group_by(.category) | map({category: .[0].category, total: map(.price) | add, count: length})' > summary.json
```
### 27. Count errors by year, month, and hour from log timestamps
```bash
cat logs.txt | grep ERROR | cut -d' ' -f1,2 | awk '{split($1,d,"-"); split($2,t,":"); print d[1]" "d[2]" "t[1]}' | sort | uniq -c
```
### 28. Filter JSON data for items with price > 100, group by category, and count items in each category
```bash
cat data.json | jq 'map(select(.price > 100)) | group_by(.category) | map({category: .[0].category, count: length})' > summary.json
```
### 29. Filter JSON data for items with price > 100, group by category, and count items in each category
```bash
cat data.json | jq 'map(select(.price > 100)) | group_by(.category) | map({category: .[0].category, count: length})' > summary.json
```
### 30. Filter JSON for expensive electronics items and export to CSV
```bash
jq -r '.items[] | select(.price > 100 and .category=="electronics") | [.id, .name, .price] | @csv' data.json > expensive_electronics.csv
```
### 31. Sum transaction amounts over $100 for active accounts and format as currency
```bash
cat data.json | jq '.[] | select(.status=="active") | .transactions | map(select(.amount > 100)) | map(.amount) | add' | awk '{printf "$%.2f\n", $1}'
```
### 32. Find 404 errors occurring more than 10 times, excluding Googlebot requests
```bash
cat access.log | grep -v 'Googlebot' | awk '{print $1, $9, $10}' | grep ' 404 ' | awk '{count[$3]++} END{for (url in count) if (count[url] > 10) print count[url], url}' | sort -nr
```
### 33. Aggregate sales data by month and region, then sort by month and sales amount
```bash
cat sales.csv | awk -F, 'NR>1{month=substr($1,6,2); region=$2; sales[month,region]+=$3} END{for (i in sales) {split(i,idx,SUBSEP); print idx[1],idx[2],sales[i]}}' | sort -k1,1n -k3,3nr
```
### 34. Summarize CSV data with revenue, profit, and margin by category
```bash
cat data.csv | awk -F, 'NR>1{a[$1]+=$2; b[$1]+=$3} END{print "Category,Revenue,Profit,Margin"; for (i in a) printf "%s,%.2f,%.2f,%.2f%%\n", i, a[i], b[i], (b[i]/a[i])*100}' > summary.csv
```
### 35. Calculate hourly averages from timestamped JSON data
```bash
cat data.json | jq -r '.[] | [.timestamp, .value] | @csv' | awk -F, '{split($1,dt,"T"); date=dt[1]; hour=substr(dt[2],1,2); data[date,hour]+=$2; count[date,hour]++} END{for (i in data) {split(i,idx,SUBSEP); print idx[1],idx[2],data[i]/count[i]}}' | sort
```
### 36. Extract unique IPs from logs, look up countries, and count IPs per country
```bash
cat logs.txt | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort | uniq | while read ip; do geoiplookup $ip | grep -oP '(?<=: ).*' | tr -d ',' | awk -v ip=$ip '{print ip, $0}'; done | sort -k2,2 | awk '{count[$2]++} END{for (country in count) print country, count[country]}' | sort -k2,2nr
```
## Networking <a name="networking"></a>
Commands for network diagnostics, monitoring, data transfer, and API interactions.
### 1. Display bandwidth usage on an network interface (e.g. enp175s0f0)
```bash
iftop -i enp175s0f0
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 2. Change network maximum transmission unit (mtu) (e.g. change to 9000)
```bash
ifconfig eth0 mtu 9000
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 3. Create a simple TCP server to receive data on port 8080 and save it to a file
```bash
nc -l -p 8080 > received_file.txt
```
### 4. Capture and display HTTP traffic on interface eth0
```bash
tcpdump -i eth0 -nn -s0 -v port 80
```
### 5. Scan all ports on a host and show only open ports
```bash
nmap -sS -p 1-65535 192.168.1.1 | grep open
```
### 6. Scan all ports on a host and show only open ports
```bash
nmap -sS -p 1-65535 192.168.1.1 | grep open
```
### 7. Persisting network configuration changes: then edit the fields: BOOTPROT, DEVICE, IPADDR, NETMASK, GATEWAY, DNS1 etc
```bash
sudo vi /etc/sysconfig/network-scripts/ifcfg-enoxxx
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 8. Create a compressed tar archive and send it to a remote server in one command
```bash
tar -czf - directory | ssh user@host "cat > backup.tar.gz"
```
### 9. Find out the http status code of a URL
```bash
curl -s -o /dev/null -w "%{http_code}" https://www.google.com
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 10. Copy a directory from a remote host to local machine using SSH and tar
```bash
ssh user@host 'tar czf - /source/dir' | tar xzf - -C /destination/dir
```
### 11. Copy a directory from a remote host to local machine using SSH and tar
```bash
ssh user@host 'tar czf - /source/dir' | tar xzf - -C /destination/dir
```
### 12. Generate an SSH key pair and copy the public key to a remote server
```bash
ssh-keygen -t ed25519 -C "user@example.com" && ssh-copy-id user@remote
```
### 13. Add multiple git hosting services to SSH known hosts
```bash
ssh-keyscan -t rsa github.com gitlab.com bitbucket.org >> ~/.ssh/known_hosts
```
### 14. List all unique ports that are being listened on
```bash
netstat -tuln | grep LISTEN | awk '{print $4}' | awk -F: '{print $NF}' | sort -n | uniq
```
### 15. List all unique ports that are being listened on
```bash
netstat -tuln | grep LISTEN | awk '{print $4}' | awk -F: '{print $NF}' | sort -n | uniq
```
### 16. List all unique ports that are being listened on
```bash
netstat -tuln | grep LISTEN | awk '{print $4}' | awk -F: '{print $NF}' | sort -n | uniq
```
### 17. Scan network for all open ports and display sorted results
```bash
nmap -sS -p- -T4 192.168.1.0/24 --open | grep -E "^[0-9]+/open" | awk '{print $1}' | sort -n
```
### 18. Count active items from a JSON API response
```bash
curl -s https://api.example.com/data | jq '.items[] | select(.status=="active")' | grep -c 'id'
```
### 19. Count active items from a JSON API response
```bash
curl -s https://api.example.com/data | jq '.items[] | select(.status=="active")' | grep -c 'id'
```
### 20. Fetch JSON data from API and convert to CSV
```bash
curl -s https://api.example.com/data | jq -r '.items[] | [.id, .name, .value] | @csv' > data.csv
```
### 21. Capture HTTP packets with data (not just SYN/ACK/FIN)
```bash
tcpdump -i eth0 -nn -s0 -v 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
```
### 22. Send a POST request with JSON data to an API endpoint
```bash
curl -s -X POST -H "Content-Type: application/json" -d '{"key":"value"}' https://api.example.com/endpoint
```
### 23. Configure iptables to block IPs that attempt more than 3 SSH connections in 60 seconds
```bash
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP
```
### 24. Find and download error logs from the last 24 hours from remote server
```bash
ssh user@host 'find /var/log -name "*.log" -mtime -1 -type f -exec grep -l "ERROR" {} \;' | xargs -I{} scp user@host:{} ./logs/
```
### 25. Measure website performance metrics with curl
```bash
curl -s -w "\nTime: %{time_total}s\nSize: %{size_download} bytes\nSpeed: %{speed_download} bytes/s\n" -o /dev/null https://example.com
```
### 26. Fetch IDs from an API and make subsequent requests for each ID
```bash
curl -s https://api.example.com/data | jq -r '.items[] | select(.status=="active") | .id' | xargs -I{} curl -s https://api.example.com/items/{}
```
### 27. Find error logs on remote server from last 24 hours and download each one
```bash
ssh user@host 'find /var/log -name "*.log" -mtime -1 -type f -exec grep -l "ERROR" {} \;' | while read logfile; do scp user@host:"$logfile" ./logs/; done
```
### 28. Scan local network for active hosts with parallel pings and sort results numerically
```bash
for ip in $(seq 1 254); do (ping -c 1 192.168.1.$ip | grep "bytes from" | awk '{print $4}' | cut -d':' -f1 &); done | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n
```
### 29. Execute GraphQL query and process results with jq
```bash
curl -s -X POST -H "Content-Type: application/json" -d '{"query":"query { users { id name email } }"}' https://api.example.com/graphql | jq '.data.users[]'
```
### 30. Capture HTTP traffic, extract and count Host headers to identify most requested domains
```bash
tcpdump -i eth0 -nn -s0 -v 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' | grep -oE 'Host: [^ ]+' | sort | uniq -c | sort -nr
```
### 31. Fetch IDs from API, then get and extract names for each active item
```bash
curl -s https://api.example.com/data | jq -r '.items[] | select(.status=="active") | .id' | xargs -I{} curl -s https://api.example.com/items/{} | jq -r '.name'
```
### 32. Log in to a website and access a protected page using cookies
```bash
curl -s -L --cookie-jar cookies.txt -d "username=user&password=pass" https://example.com/login && curl -s -L --cookie cookies.txt https://example.com/protected-page
```
### 33. List all listening ports and the processes using them
```bash
netstat -tunapl | awk '{print $4,$7}' | grep -E '[0-9]\.[0-9]\.[0-9]\.[0-9]:[0-9]+.*LISTEN.*' | awk '{split($1,a,":"); print a[2],"is used by",substr($2,1,index($2,"/")-1)}' | sort -n
```
### 34. Scan network for open ports and display formatted results by IP and service
```bash
nmap -sS -p- -T4 192.168.1.0/24 --open | grep -E "^[0-9]+/open" | awk '{print $1,$3}' | sed 's|/| |g' | awk '{print $3,$1,$2}' | sort | uniq | awk '{printf "%-15s %-5s %-s\n", $1, $2, $3}'
```
### 35. Query GraphQL API with authentication, filter results, and export to CSV
```bash
curl -s -X POST -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"query":"query { users(status: \"active\") { id name email } }"}' https://api.example.com/graphql | jq '.data.users[] | select(.email | contains("@example.com"))' | jq -r '[.id, .name, .email] | @csv' > active_users.csv
```
## Scripting Techniques <a name="scripting_techniques"></a>
Advanced bash scripting patterns, functions, and control structures for building robust scripts.
### 1. List environment variables (e.g. PATH): list of directories separated by a colon
```bash
echo $PATH
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 2. Echo size of variable
```bash
echo ${#foo}
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 3. Some handy environment variables
```bash
$0   :name of shell or shell script.
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 4. Loop from 1 to 10, printing each number with a 1-second delay
```bash
for i in {1..10}; do echo $i; sleep 1; done
```
### 5. Loop from 1 to 10, printing each number with a 1-second delay
```bash
for i in {1..10}; do echo $i; sleep 1; done
```
### 6. Execute a command in each subdirectory
```bash
for dir in */; do (cd "$dir" && command); done
```
### 7. Define a bash function to create a compressed backup of a directory
```bash
function backup() { tar -czf "$1.tar.gz" "$1"; }
```
### 8. Define a bash function to create a compressed backup of a directory
```bash
function backup() { tar -czf "$1.tar.gz" "$1"; }
```
### 9. Rename all .txt files in the current directory to .md files
```bash
for file in *.txt; do mv "$file" "${file%.txt}.md"; done
```
### 10. Process each line in a file using a while loop
```bash
while read line; do echo "Processing $line"; done < file.txt
```
### 11. Process each line in a file using a while loop
```bash
while read line; do echo "Processing $line"; done < file.txt
```
### 12. Check if a file exists and print appropriate message using logical operators
```bash
[ -f "$file" ] && echo "File exists" || echo "File does not exist"
```
### 13. Create and iterate through a bash array
```bash
array=(one two three); for item in "${array[@]}"; do echo "$item"; done
```
### 14. Count lines in Python files that import modules and sort by line count
```bash
find . -type f -name "*.py" | xargs grep -l "import" | xargs wc -l | sort -nr
```
### 15. Set up a trap to catch signals and perform cleanup before exiting
```bash
trap 'echo "Caught signal, cleaning up..."; rm -f temp_file; exit 1' INT TERM
```
### 16. Check if a string contains only numbers using regex in bash
```bash
if [[ "$string" =~ ^[0-9]+$ ]]; then echo "Numeric"; else echo "Non-numeric"; fi
```
### 17. Check if a string contains only numbers using regex in bash
```bash
if [[ "$string" =~ ^[0-9]+$ ]]; then echo "Numeric"; else echo "Non-numeric"; fi
```
### 18. Use a case statement to handle different command arguments
```bash
case "$1" in start) echo "Starting";; stop) echo "Stopping";; *) echo "Unknown command";; esac
```
### 19. Use a case statement to handle different command arguments
```bash
case "$1" in start) echo "Starting";; stop) echo "Stopping";; *) echo "Unknown command";; esac
```
### 20. Process CSV data line by line with field separation
```bash
while IFS=, read -r name email; do echo "Sending email to $name at $email"; done < contacts.csv
```
### 21. Rename files interactively with user input
```bash
for file in *.jpg; do read -p "Enter new name for $file: " newname; mv "$file" "$newname.jpg"; done
```
### 22. Run multiple tasks in parallel with random delays and wait for completion
```bash
for i in {1..10}; do (sleep $((RANDOM % 5)); echo "Task $i completed") & done; wait; echo "All tasks completed"
```
### 23. Count lines in all text files and sort by line count
```bash
for file in *.txt; do [ -f "$file" ] && awk -v filename="$file" 'END {print filename, NR}' "$file"; done | sort -nrk 2
```
### 24. Validate phone number format using regex in bash
```bash
if [[ "$string" =~ ^[0-9]{3}-[0-9]{3}-[0-9]{4}$ ]]; then echo "Valid phone number"; else echo "Invalid phone number"; fi
```
### 25. Set up a trap to catch signals and perform cleanup before exiting
```bash
trap 'echo "Caught signal, cleaning up..."; rm -f temp_*; exit 1' INT TERM; echo "Script running, press Ctrl+C to test trap"
```
### 26. Use associative arrays to create a key-value map from a file
```bash
declare -A map; while read -r key value; do map["$key"]="$value"; done < data.txt; for key in "${!map[@]}"; do echo "$key: ${map[$key]}"; done
```
### 27. Create error handling function with custom messages and exit codes
```bash
function error_exit() { echo "${PROGNAME}: ${1:-"Unknown Error"}" 1>&2; exit ${2:-1}; }; cd /some/directory || error_exit "Cannot change to required directory"
```
### 28. Create a logging function with timestamp and log level
```bash
function log() { local level="$1"; shift; echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $@" >> app.log; }; log "INFO" "Application started"; log "ERROR" "Something went wrong"
```
### 29. Set up automatic cleanup of temporary files using trap and EXIT signal
```bash
function cleanup() { echo "Cleaning up temporary files..."; rm -f "$TEMPFILE"; echo "Done."; }; trap cleanup EXIT; TEMPFILE=$(mktemp); echo "Working with temporary file: $TEMPFILE"
```
### 30. Create an interactive menu with select and case statements
```bash
select option in "Option 1" "Option 2" "Option 3" "Quit"; do case $option in "Option 1") echo "Selected option 1" ;; "Option 2") echo "Selected option 2" ;; "Option 3") echo "Selected option 3" ;; "Quit") break ;; *) echo "Invalid option" ;; esac; done
```
### 31. Create a confirmation function and use it before performing destructive operations
```bash
function confirm() { read -r -p "${1:-Are you sure? [y/N]} " response; case "$response" in [yY][eE][sS]|[yY]) true;; *) false;; esac; }; if confirm "Delete all temporary files?"; then find /tmp -type f -delete; echo "Files deleted"; else echo "Operation cancelled"; fi
```
### 32. Create a retry function with exponential backoff and use it with curl
```bash
function retry() { local retries=$1; shift; local count=0; until "$@"; do exit=$?; count=$((count + 1)); if [ $count -lt $retries ]; then echo "Retry $count/$retries exited $exit, retrying in $count seconds..."; sleep $count; else echo "Retry $count/$retries exited $exit, no more retries left."; return $exit; fi; done; return 0; }; retry 5 curl -s https://example.com
```
### 33. Create a function to extract various archive formats
```bash
function extract() { if [ -f "$1" ]; then case "$1" in *.tar.bz2) tar xjf "$1" ;; *.tar.gz) tar xzf "$1" ;; *.bz2) bunzip2 "$1" ;; *.rar) unrar e "$1" ;; *.gz) gunzip "$1" ;; *.tar) tar xf "$1" ;; *.tbz2) tar xjf "$1" ;; *.tgz) tar xzf "$1" ;; *.zip) unzip "$1" ;; *.Z) uncompress "$1" ;; *) echo "'$1' cannot be extracted" ;; esac; else echo "'$1' is not a valid file"; fi; }
```
### 34. Parse YAML configuration file and create shell variables from it
```bash
function parse_yaml() { local prefix=$2; local s='[[:space:]]*' w='[a-zA-Z0-9_]*' fs=$(echo @|tr @ '\034'); sed -ne "s|^$s||;s|$s#.*||;s|$s$||;s|$s:$s| |;p" $1 | awk -F" " '{indent = length($1)/2; for (i in keys) {if (i > indent) {delete keys[i]}}; if (length($3) > 0) { key=keys[indent]; if (key == "") {key=$2} else {key=key"_"$2}; printf("%s%s%s=\"%s\"\n", "'$prefix'",key,"'$fs'", $3)}; keys[indent+1]=$2}' | sed -e 's|\"|\\\"|g' | awk -F$fs '{printf "%s\n", $1}'; }; eval $(parse_yaml config.yml "config_")
```
## Process Management <a name="process_management"></a>
Commands for monitoring, controlling, and optimizing running processes and system resources.
### 1. Display process tree showing parent-child relationships
```bash
ps -eo pid,user,cmd --forest
```
### 2. Count the number of httpd processes running without showing grep in results
```bash
ps -ef | grep [h]ttpd | wc -l
```
### 3. Find processes in uninterruptible sleep (usually I/O)
```bash
ps aux | awk '{if($8=="D") print $0}'
```
### 4. Run a command that continues running after you log out, with output redirected to a file
```bash
nohup long_running_command > output.log 2>&1 &
```
### 5. Run a command that continues running after you log out, with output redirected to a file
```bash
nohup long_running_command > output.log 2>&1 &
```
### 6. Find processes matching a pattern and reduce their priority
```bash
pgrep -f 'process_pattern' | xargs -I{} renice +10 {}
```
### 7. Find processes matching a pattern and reduce their priority
```bash
pgrep -f 'process_pattern' | xargs -I{} renice +10 {}
```
### 8. Show process tree around nginx processes
```bash
ps -eo pid,ppid,cmd --forest | grep -B2 -A2 '[n]ginx'
```
### 9. List all processes running as www-data user
```bash
ps -eo pid,user,group,comm | grep '^[0-9]\+ www-data'
```
### 10. Show the top 10 processes consuming the most memory
```bash
ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 10
```
### 11. Show the top 10 processes consuming the most memory
```bash
ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 10
```
### 12. Show the top 10 processes consuming the most CPU
```bash
ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 10
```
### 13. Show all nginx processes with start time and elapsed time, sorted by start time
```bash
ps -eo pid,lstart,etime,cmd | grep '[n]ginx' | sort -k 2
```
### 14. Set low I/O priority for processes matching a pattern
```bash
pgrep -f 'process_pattern' | xargs -I{} ionice -c2 -n7 -p {}
```
### 15. List all non-kernel processes running as root
```bash
ps -eo pid,user,cmd | grep '^[0-9]\+ root' | grep -v '\[.*\]'
```
### 16. List all non-kernel processes running as root
```bash
ps -eo pid,user,cmd | grep '^[0-9]\+ root' | grep -v '\[.*\]'
```
### 17. Find and kill all processes matching a name without showing the grep process itself
```bash
ps aux | grep [p]rocess_name | awk '{print $2}' | xargs kill -9
```
### 18. Find and kill all processes matching a name without showing the grep process itself
```bash
ps aux | grep [p]rocess_name | awk '{print $2}' | xargs kill -9
```
### 19. Find and kill all processes matching a name without showing the grep process itself
```bash
ps aux | grep [p]rocess_name | awk '{print $2}' | xargs kill -9
```
### 20. Show top 10 CPU-consuming processes that are actually using CPU
```bash
ps aux | awk '{if($3>0.0) print $0}' | sort -nrk 3,3 | head -n 10
```
### 21. Find and kill all Firefox processes
```bash
ps aux | grep -v grep | grep -i "firefox" | awk '{print $2}' | xargs kill -9
```
### 22. Count open file descriptors for all Python processes
```bash
ps -eo pid,cmd | grep '[p]ython' | awk '{print $1}' | xargs -I{} ls -l /proc/{}/fd | wc -l
```
### 23. Show memory usage details for all MongoDB processes
```bash
ps -eo pid,cmd | grep '[m]ongod' | awk '{print $1}' | xargs -I{} pmap {} | grep -i 'total' | awk '{print $2}'
```
### 24. Find blocked threads in Java processes
```bash
ps -eo pid,cmd | grep '[j]ava' | awk '{print $1}' | xargs -I{} bash -c 'echo "PID: {}"; jstack {} | grep -A 1 "BLOCKED"'
```
### 25. Show executables of all non-kernel root processes
```bash
ps -eo pid,user,cmd | grep '^[0-9]\+ root' | grep -v '\[.*\]' | awk '{print $1}' | xargs -I{} ls -l /proc/{}/exe 2>/dev/null
```
### 26. Show top 10 memory-consuming processes with formatted output
```bash
ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 10 | awk '{printf "%-6s %-6s %-50.50s %-5s %-5s\n", $1, $2, $3, $4, $5}'
```
### 27. Check file descriptor limits for all nginx processes
```bash
ps -eo pid,cmd | grep '[n]ginx' | awk '{print $1}' | xargs -I{} bash -c 'echo "PID: {}"; cat /proc/{}/limits | grep "Max open files"'
```
### 28. Find top memory-consuming processes with formatted output saved to file
```bash
ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 10 | awk '{printf "%-6s %-6s %-50.50s %-5s %-5s\n", $1, $2, $3, $4, $5}' | tee memory_hogs.txt
```
### 29. Find blocked threads in all Java processes and save details to file
```bash
ps -eo pid,cmd | grep '[j]ava' | awk '{print $1}' | xargs -I{} bash -c 'echo "PID: {}"; jstack {} | grep -A 2 -B 2 "BLOCKED"' > java_blocked_threads.txt
```
### 30. Find non-standard executables running as root (potential security issue)
```bash
ps -eo pid,user,cmd | grep '^[0-9]\+ root' | grep -v '\[.*\]' | awk '{print $1}' | xargs -I{} ls -l /proc/{}/exe 2>/dev/null | grep -v -E '/bin/|/sbin/|/usr/bin/'
```
### 31. Report processes using more than 10% CPU with descriptive messages
```bash
ps -eo pid,user,group,comm,%cpu,%mem --sort=-%cpu | head -n 20 | awk '$5 > 10.0 {print}' | while read pid user group comm cpu mem; do echo "$user's $comm process ($pid) using $cpu% CPU"; done
```
## System Administration <a name="system_administration"></a>
Commands for system monitoring, maintenance, log analysis, and administrative tasks.
### 1. Show processes using port 80
```bash
lsof -i :80
```
### 2. Show the last 20 system logins
```bash
last | head -n 20
```
### 3. Collect and summarize all hardware info of your machine: Other options are: [ -html ]  [ -short ]  [ -xml ]  [ -json ]  [ -businfo ]  [ -sanitize ] ,etc
```bash
lshw -json >report.json
```
*Source: GitHub: onceupon/Bash-Oneliner*
### 4. Show size of log files and directories, sorted by size
```bash
du -sh /var/log/* | sort -hr
```
### 5. List all failed systemd services
```bash
systemctl list-units --state=failed
```
### 6. Find all SUID executables on the system
```bash
find / -type f -perm -4000 -ls 2>/dev/null
```
### 7. Show all error messages from system logs in the last hour
```bash
journalctl --since "1 hour ago" | grep -i error
```
### 8. Show all error messages from system logs in the last hour
```bash
journalctl --since "1 hour ago" | grep -i error
```
### 9. Delete log files older than 30 days
```bash
find /var/log -name "*.log" -type f -mtime +30 -delete
```
### 10. Delete log files older than 30 days
```bash
find /var/log -name "*.log" -type f -mtime +30 -delete
```
### 11. Check disk usage and alert if any filesystem is over 90% full
```bash
df -h | awk '$5 > 90 {print $1 " is at " $5 " capacity"}'
```
### 12. Check disk usage and alert if any filesystem is over 90% full
```bash
df -h | awk '$5 > 90 {print $1 " is at " $5 " capacity"}'
```
### 13. Show processes using HTTP and HTTPS ports with concise output
```bash
lsof -i :80,443 | awk '{print $1,$2,$3,$9}' | sort | uniq
```
### 14. Find configuration files containing a specific parameter
```bash
find /etc -type f -name "*.conf" -exec grep -l "parameter" {} \;
```
### 15. Find files larger than 100MB on the current filesystem and sort by size
```bash
find / -xdev -type f -size +100M -exec ls -lh {} \; | sort -k5,5hr
```
### 16. Find files larger than 100MB on the current filesystem and sort by size
```bash
find / -xdev -type f -size +100M -exec ls -lh {} \; | sort -k5,5hr
```
### 17. Show top 10 users with most logins
```bash
last | grep -v "^reboot" | awk '{print $1}' | sort | uniq -c | sort -nr | head -n 10
```
### 18. Count and sort error and warning messages from system logs in the last hour
```bash
journalctl --since "1 hour ago" | grep -i "error\|failed\|warning" | sort | uniq -c | sort -nr
```
### 19. Generate report of all SUID executables on the system
```bash
find / -type f -perm -4000 -ls 2>/dev/null | awk '{print $3,$5,$6,$11}' > suid_files_report.txt
```
### 20. Check disk usage and email alert if any filesystem is over 90% full
```bash
df -h | awk '$5 > 90 {print $1 " is at " $5 " capacity"}' | mail -s "Disk space alert" admin@example.com
```
### 21. Generate report of 20 largest files on the current filesystem
```bash
find / -xdev -type f -size +100M -exec ls -lh {} \; | sort -k5,5hr | head -n 20 > large_files_report.txt
```
### 22. Find and backup configuration files containing a specific parameter
```bash
find /etc -type f -name "*.conf" -exec grep -l "parameter" {} \; | xargs -I{} cp {} /root/config_backup/
```
### 23. List listening ports with formatted columns for process name, PID, user, and port
```bash
lsof -i -P -n | grep LISTEN | awk '{printf "%-10s %-6s %-10s %-8s %s\n", $1, $2, $3, $9, $10}' | column -t
```
### 24. Find and report log directories using gigabytes of space
```bash
du -sh /var/log/* | sort -hr | awk '$1 ~ /G/ {print $1,$2}' | mail -s "Large log directories" admin@example.com
```
### 25. Archive log files older than 30 days with compression
```bash
find /var/log -name "*.log" -type f -mtime +30 -exec bash -c 'gzip "{}" && mv "{}.gz" "/var/log/archive/$(basename {}).gz"' \;
```
### 26. Generate detailed report of all failed systemd services
```bash
systemctl list-units --state=failed --no-pager | awk 'NR>1 {print $1}' | xargs -I{} systemctl status {} > failed_services_report.txt
```
### 27. Generate tabular report of 20 largest files on the current filesystem
```bash
find / -xdev -type f -size +100M -exec ls -lh {} \; | sort -k5,5hr | head -n 20 | awk '{printf "%s\t%s\n", $5, $9}' > large_files_report.txt
```
### 28. Archive old logs with compression into year-month directories
```bash
find /var/log -name "*.log" -type f -mtime +30 -exec bash -c 'gzip -9 "{}" && mv "{}.gz" "/var/log/archive/$(date -r "{}" +%Y-%m)/$(basename {}).gz"' \;
```
### 29. Check disk usage, generate alerts, and log warnings for filesystems over 90% full
```bash
df -h | awk '$5 > 90 {print $1 " is at " $5 " capacity"}' | while read line; do echo "ALERT: $line"; logger -p user.warning "DISK SPACE ALERT: $line"; done
```
### 30. Extract, count, and format recent errors and warnings from system logs
```bash
journalctl --since "1 hour ago" | grep -i "error\|failed\|warning" | sort | uniq -c | sort -nr | awk '{printf "%4d %s\n", $1, substr($0, index($0,$2))}' > recent_errors.txt
```
## Performance Optimization <a name="performance_optimization"></a>
Commands that leverage parallelism and other techniques to maximize performance and efficiency.
### 1. Run a CPU-intensive backup with the lowest priority to avoid impacting system performance
```bash
nice -n 19 tar -czf backup.tar.gz /home/user
```
### 2. Create a tar archive and compress it with maximum compression using multiple CPU cores
```bash
tar -c directory | pigz -9 > directory.tar.gz
```
### 3. Benchmark system I/O performance by writing 1GB of zeros
```bash
dd if=/dev/zero of=/dev/null bs=1M count=1000
```
### 4. Create a tar archive and compress it with maximum compression using multiple CPU cores
```bash
tar -c directory | pigz -9 > directory.tar.gz
```
### 5. Benchmark system I/O performance by writing 1GB of zeros
```bash
dd if=/dev/zero of=/dev/null bs=1M count=1000
```
### 6. Run rsync with low I/O priority to minimize impact on system responsiveness
```bash
ionice -c2 -n7 rsync -av source/ destination/
```
### 7. Search for pattern in Python files with progress visualization
```bash
grep -r --include="*.py" pattern . | pv > results.txt
```
### 8. Create a tar archive and compress it with maximum compression using all available CPU cores
```bash
tar -c directory | pigz -9 -p $(nproc) > directory.tar.gz
```
### 9. Optimize PNG images in parallel using all available CPU cores
```bash
find . -type f -name "*.png" | parallel -j$(nproc) optipng {}
```
### 10. Process a large file in parallel chunks for faster grep operations
```bash
cat large_file.txt | parallel --pipe --block 10M 'grep pattern'
```
### 11. Compress multiple log files in parallel with maximum compression
```bash
find . -type f -name "*.log" | parallel -j$(nproc) 'gzip -9 {}'
```
### 12. Run rsync with lowest CPU and I/O priority to minimize system impact
```bash
ionice -c2 -n7 nice -n 19 rsync -av --progress source/ destination/
```
### 13. Search for files containing a pattern using 4 parallel processes
```bash
find . -type f -name "*.txt" -print0 | xargs -0 -P4 grep -l "pattern"
```
### 14. Search for files containing a pattern using 4 parallel processes
```bash
find . -type f -name "*.txt" -print0 | xargs -0 -P4 grep -l "pattern"
```
### 15. Search for files containing a pattern using all available CPU cores
```bash
find . -type f -name "*.txt" -print0 | xargs -0 -P$(nproc) -I{} grep -l "pattern" {}
```
### 16. Resize all JPG images in parallel using 8 CPU cores
```bash
find . -type f -name "*.jpg" | parallel -j8 convert {} -resize 800x600 {.}_resized.jpg
```
### 17. Resize all JPG images in parallel using 8 CPU cores
```bash
find . -type f -name "*.jpg" | parallel -j8 convert {} -resize 800x600 {.}_resized.jpg
```
### 18. Resize all JPG images in parallel using 8 CPU cores
```bash
find . -type f -name "*.jpg" | parallel -j8 convert {} -resize 800x600 {.}_resized.jpg
```
### 19. Convert video files in parallel using 4 CPU cores
```bash
find . -type f -name "*.mp4" | parallel -j4 ffmpeg -i {} -vcodec h264 -acodec aac {.}.mp4
```
### 20. Sort multiple CSV files in parallel using all available CPU cores
```bash
find . -type f -name "*.csv" | parallel -j$(nproc) 'sort -t, -k2,2 {} > {}.sorted && mv {}.sorted {}'
```
### 21. Create compressed archive with progress bar and multi-core compression
```bash
tar -c directory | pv -s $(du -sb directory | awk '{print $1}') | pigz -9 -p$(nproc) > directory.tar.gz
```
### 22. Resize all JPG images in parallel using all available CPU cores and replace originals
```bash
find . -type f -name "*.jpg" | parallel -j$(nproc) 'convert {} -resize 800x600 {.}_resized.jpg && rm {}'
```
### 23. Count pattern occurrences in a large file by processing chunks in parallel
```bash
cat large_file.txt | parallel --pipe --block 10M 'grep pattern | wc -l' | awk '{sum+=$1} END {print sum}'
```
### 24. Count pattern occurrences in multiple gzipped files in parallel
```bash
find . -type f -name "*.gz" | parallel -j$(nproc) 'zcat {} | grep -c "pattern"' | awk '{sum+=$1} END {print sum}'
```
### 25. Optimize PNG images in parallel using two-step compression
```bash
find . -type f -name "*.png" | parallel -j$(nproc) 'pngquant --force --quality=65-80 --ext=.png {} && optipng -quiet {}'
```
### 26. Search PDF files for sensitive content in parallel with ETA
```bash
find . -type f -name "*.pdf" | parallel -j$(nproc) --eta 'pdftotext {} - | grep -q "confidential" && echo {} contains confidential information'
```
### 27. Convert video files to H.264/AAC in parallel with optimized settings
```bash
find . -type f -name "*.mp4" | parallel -j4 'ffmpeg -i {} -c:v libx264 -preset slow -crf 22 -c:a aac -b:a 128k {.}.mp4.new && mv {.}.mp4.new {}'
```
### 28. Process large file with parallel grep and dual progress meters
```bash
cat large_file.txt | pv -cN original | parallel --pipe --block 10M -j$(nproc) 'grep -E "pattern1|pattern2"' | pv -cN filtered > filtered_output.txt
```
### 29. Optimize JPEG images in parallel with progress indicator and ETA
```bash
find . -type f -name "*.jpg" | parallel --progress --eta -j$(nproc) 'convert -strip -interlace Plane -gaussian-blur 0.05 -quality 85% {} {}.optimized && mv {}.optimized {}'
```
### 30. Convert videos to web-optimized format in parallel with progress bar
```bash
find . -type f -name "*.mp4" | parallel -j4 --bar 'ffmpeg -i {} -c:v libx264 -preset medium -crf 22 -c:a aac -b:a 128k -movflags +faststart {.}.mp4.new && mv {.}.mp4.new {}'
```
## Security <a name="security"></a>
Commands for security auditing, hardening, encryption, and threat detection.
### 1. Generate a secure random 32-byte password encoded in base64
```bash
openssl rand -base64 32
```
### 2. Secure cron directories by ensuring they're owned by root
```bash
chown -R root:root /etc/cron*
```
### 3. Search for passwords in configuration files
```bash
grep -r password /etc/ 2>/dev/null
```
### 4. Find files with no valid owner or group (security risk)
```bash
find / -nouser -o -nogroup 2>/dev/null
```
### 5. Find all SUID executables on the system
```bash
find / -type f -perm -4000 -ls 2>/dev/null
```
### 6. Find all SUID executables on the system
```bash
find / -type f -perm -4000 -ls 2>/dev/null
```
### 7. Generate a secure Ed25519 SSH key pair
```bash
ssh-keygen -t ed25519 -C "user@example.com"
```
### 8. Find world-writable files (potential security risk)
```bash
find / -type f -perm -2 ! -type l -ls 2>/dev/null
```
### 9. Encrypt a file using AES-256 encryption
```bash
openssl enc -aes-256-cbc -salt -in file.txt -out file.enc -k password
```
### 10. Encrypt a file using AES-256 with PBKDF2 key derivation and 100,000 iterations
```bash
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -in file.txt -out file.enc
```
### 11. Generate a secure Ed25519 SSH key with 100 KDF rounds
```bash
ssh-keygen -t ed25519 -a 100 -C "user@example.com" -f ~/.ssh/id_ed25519_secure
```
### 12. Generate a secure random 48-byte password and encrypt it with GPG
```bash
openssl rand -base64 48 | gpg --symmetric --cipher-algo AES256 -o password.gpg
```
### 13. List processes listening on non-localhost network interfaces (potential security exposure)
```bash
lsof -i -P -n | grep LISTEN | grep -v -E "127.0.0.1|::1" | awk '{print $1,$3,$9}'
```
### 14. Find SUID/SGID files outside standard system directories (potential security risk)
```bash
find / -type f -perm -4000 -o -perm -2000 -ls 2>/dev/null | grep -v -E '/bin/|/sbin/|/usr/'
```
### 15. Configure iptables to track new connections to SSH, HTTP, and HTTPS ports
```bash
iptables -A INPUT -p tcp -m multiport --dports 22,80,443 -m state --state NEW -m recent --set
```
### 16. List processes listening on non-localhost interfaces (potential security exposure)
```bash
lsof -i -P -n | grep -v ESTABLISHED | grep -v "127.0.0.1" | awk '$5 == "LISTEN" {print $1,$3,$9}' | sort | uniq
```
### 17. Find world-writable files outside virtual filesystems (security risk)
```bash
find / -type f -perm -2 ! -type l -ls 2>/dev/null | grep -v -E '/proc/|/sys/|/dev/' | awk '{print $3,$5,$6,$11}'
```
### 18. Find sudo commands in all users' bash history
```bash
find /home -type f -name ".bash_history" -exec grep -l "sudo" {} \; | xargs cat | grep -E "sudo|su -" | sort | uniq
```
### 19. Encrypt sensitive file with strong encryption and securely delete original
```bash
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -in sensitive.txt -out sensitive.enc && shred -zvu -n 10 sensitive.txt
```
### 20. Search for plaintext passwords in configuration files
```bash
grep -r --include="*.conf" --include="*.ini" -E "password|passwd|pass" /etc/ 2>/dev/null | grep -v "^#" | grep -v -E "shadow|pam"
```
### 21. Configure iptables to block IPs that attempt more than 3 SSH connections in 60 seconds
```bash
sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP
```
### 22. Find and count IP addresses with failed password attempts in log files
```bash
find . -type f -name "*.log" -exec grep -l "Failed password" {} \; | xargs cat | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq -c | sort -nr
```
### 23. Find and count IP addresses with failed password attempts in log files
```bash
find . -type f -name "*.log" -exec grep -l "Failed password" {} \; | xargs cat | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq -c | sort -nr
```
### 24. Find and report SUID/SGID files outside standard system directories
```bash
find / -type f -perm -4000 -o -perm -2000 -ls 2>/dev/null | grep -v -E '/bin/|/sbin/|/usr/' | awk '{printf "%-10s %-10s %s\n", $5, $6, $11}' > suid_sgid_report.txt
```
### 25. Find and report world-writable files outside virtual filesystems with count
```bash
find / -type f -perm -2 ! -type l -ls 2>/dev/null | grep -v -E '/proc/|/sys/|/dev/' | awk '{printf "%-10s %-10s %s\n", $5, $6, $11}' | tee world_writable_files.txt | wc -l
```
### 26. Find top 20 IP addresses with failed password attempts across all auth logs
```bash
find /var/log -type f -name "auth.log*" -exec grep -l "Failed password" {} \; | xargs cat | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq -c | sort -nr | head -n 20
```
### 27. Find IPs with multiple failed login attempts and block them with iptables
```bash
find /var/log -type f -name "auth.log*" -exec zgrep -h "Failed password" {} \; | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq -c | sort -nr | awk '$1 > 10 {print $2}' | while read ip; do iptables -A INPUT -s $ip -j DROP; echo "Blocked $ip due to failed login attempts"; done
```
## Conclusion
This collection of 500+ powerful bash command combinations demonstrates the versatility and power of the bash shell for a wide range of programming and system administration tasks. By studying and adapting these examples, you can enhance your command-line skills and solve complex problems more efficiently.
The examples in this document range from everyday utilities to advanced multi-step pipelines that leverage the full power of Unix philosophy: combining simple tools to perform complex operations. Many of these commands can be further customized and incorporated into larger scripts or workflows.
For Claude Code specifically, these bash commands can be particularly useful when:
- Processing and transforming data files- Automating repetitive tasks- Performing system diagnostics and optimization- Extracting and analyzing information from logs and other text sources- Building data pipelines and ETL processes- Implementing security measures and audits
Continue to explore the power of bash by combining these examples and creating your own command pipelines tailored to your specific needs.