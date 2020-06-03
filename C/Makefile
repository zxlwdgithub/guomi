CC=gcc -g  $(CFLAGS) -DLINUX -w
SHARED_FLAG = -fPIC -shared

PROJECT = test_demo 
PROJECT2 = test_sm2

INC  = -I./ 
OBJ = sm2_encrypt_and_decrypt.o sm2_create_key_pair.o
OBJ1 = test_sm2_encrypt_and_decrypt.o test_demo.o
OBJ2 = test_sm2.o

MODULE = -L/usr/local/lib/ -lcrypto -lssl

all : ${OBJ}  ${OBJ1} ${OBJ2} $(PROJECT) $(PROJECT2)

$(PROJECT) :
	$(CC) ${OBJ} ${OBJ1} -o $(PROJECT) $(INC) $(MODULE)

$(PROJECT2) :
	$(CC) ${OBJ} ${OBJ2} -o $(PROJECT2) $(INC) $(MODULE)

clean:
	rm -rf *.o *.a *.so  $(PROJECT) $(PROJECT2)

%.o : %.cpp
	$(CC) $(SHARED_FLAG) -c $< $(INC)
%.o : %.c
	$(CC) $(SHARED_FLAG) -c $< $(INC)
