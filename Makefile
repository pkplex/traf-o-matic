objects = main.o tom.o
sources = main.c tom.c
execname = TOM
cflags = -Wall
libs = -lpcap	

nosy: $(objects) 
	gcc $(cflags) -o $(execname) $(objects) $(libs)

$(objects): $(sources)
	gcc $(cflags) -c $(sources) 

clean:
	rm $(objects) $(execname)
