  all: g++ -c euclideandistance.cpp -ltfhe-spqlios-fma -std=gnu++11 -lpthread
	g++ -c tfhedistance.cpp -ltfhe-spqlios-fma -std=gnu++11 -lpthread
	g++ euclideandistance.o tfhedistance.o -o euclideandistance -ltfhe-spqlios-fma -std=gnu++11 -lpthread

  clean: 
	  $(RM) myprog
