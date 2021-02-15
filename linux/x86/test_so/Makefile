objects = test_so.o

test_so : $(objects)
	cc -o test_so.so $(objects) -shared -m32

.PHONY : clean
clean :
	-rm test_so.so $(objects)