netstat -antp | grep "ESTABLISHED" > info.txt
cat info.txt | cut -d " " -f23 | cut -d ":" -f1 | sed 's/        //' > ips.txt
cat info.txt
