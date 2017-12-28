all = oicq.o List.o 
OicqAnalyis : $(all)
	clang -o OicqAnalyis $(all) -l pcap

oicq.o : oicq.c List.h List.o
	clang -c oicq.c

List.o : List.c List.h
	clang -c List.c 

clean :
	rm $(all)
