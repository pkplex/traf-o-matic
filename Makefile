objects = main.o tom.o strlcat.o strlcpy.o
sources = main.c tom.c strlcat.c strlcpy.c
execname = TOM
cflags = -Wall
libs = -lpcap	

nosy: $(objects) 
	gcc $(cflags) -o $(execname) $(objects) $(libs)

$(objects): $(sources)
	gcc $(cflags) -c $(sources) 

clean:
	rm $(objects) $(execname)
