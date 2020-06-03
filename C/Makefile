CC=gcc -g  $(CFLAGS) -DLINUX -w
SHARED_FLAG = -fPIC -shared

PROJECT = test_demo

INC  = -I./ 
OBJ = sm2_encrypt_and_decrypt.o sm2_create_key_pair.o test_sm2_encrypt_and_decrypt.o test_demo.o

MODULE = -L/usr/local/lib/ -lcrypto -lssl

all : ${OBJ} $(PROJECT)

$(PROJECT) :
	$(CC) ${OBJ} -o $(PROJECT) $(INC) $(MODULE)

clean:
	rm -rf *.o *.a *.so

%.o : %.cpp
	$(CC) $(SHARED_FLAG) -c $< $(INC)
%.o : %.c
	$(CC) $(SHARED_FLAG) -c $< $(INC)
