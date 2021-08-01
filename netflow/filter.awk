#!/bin/awk -f
BEGIN {
	FS="[ =]";
}
$1=="tcp"{
	printf "%-8s src %-15s dst %-15s packets %6d bytes %d\n", $1,$11,$13,$19+$31,$21+$33;
}
$1=="udp"{
	printf "%-8s src %-15s dst %-15s packets %6d bytes %d\n", $1,$10,$12,$18+$31,$20+$33;
}
$1=="unknown"{
	printf "%-8s src %-15s dst %-15s packets %6d bytes %d\n", $1,$6,$8,$10+$19,$12+$21;
}
