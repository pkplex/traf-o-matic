objects = main.o tom.o
sources = main.c tom.c


# objects = main.o TOMCapPacket.o TOMCap.o TOMNode.o TOMAddr.o TOM.o TOMSyslog.o
# sources = main.cpp TOMCapPacket.cpp TOMCap.cpp TOMNode.cpp TOMAddr.cpp TOM.cpp TOMSyslog.cpp

# objects = main.o TOMCapPacket.o
# sources = main.cpp TOMCapPacket.cpp


# objects = main.o TOMAddr.o
# sources = main.cpp TOMAddr.cpp




# objects = main.o TOMCap.o TOMCapPacket.o TOM.o TOMAddr.o TOMNode.o
# sources = main.cpp TOMCap.cpp TOMCapPacket.cpp TOM.cpp TOMAddr.cpp TOMNode.cpp
execname = TOM
cflags = -Wall 	
libshit = -lpcap	

# now give target as lab1 with objects as variable dependencies + command line
nosy: $(objects) 
	gcc $(cflags) -o $(execname) $(objects) $(libshit)


# build all le objects 
$(objects): $(sources)
	gcc $(cflags) -c $(sources) 


# clean up stuff...
clean:
	rm $(objects) $(execname)
