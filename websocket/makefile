
CC = g++-4.8
LD = g++-4.8
RM = rm -rf

BASEDIR	= .
SRCDIR	= $(BASEDIR)/src
PREFIX	= 

# add your source files here
SRCS = \
    main.cpp \
    p11util.cpp \
    wsserver.cpp

RELEASE=$(addprefix $(BASEDIR)/release/, $(SRCS:.cpp=.o))

DEFINES = -std=c++11 -fPIC -D_DEBUG -DLINUX -DOS_LINUX -D_THREAD_SAFE -D_REENTRANT -DUSE_PTHREADS -Wno-deprecated

INCLUDES = \
	-I./include 	\
    -I./include/RSA 	\
	-I$(OPENSSLDIR)/openssl
     

LIBS = $(OPENSSLDIR)/libcrypto.a -ldl -lpthread

CCFLAGS = -c $(DEFINES) $(INCLUDES)


all : wsserver

$(RELEASE) : $(BASEDIR)/release/%.o : $(SRCDIR)/%.cpp
	$(CC) $(CCFLAGS) $< -o $@

reldir :
	@if test -d $(BASEDIR)/release; then echo -e "\n" $(BASEDIR)/release exists ; else mkdir $(BASEDIR)/release; fi


wsserver : reldir $(RELEASE)
	$(LD) \
    $(BASEDIR)/release/main.o \
    $(BASEDIR)/release/p11util.o \
    $(BASEDIR)/release/wsserver.o \
	$(LIBS) -o $(BASEDIR)/release/wsserver


clean:
	$(RM) $(BASEDIR)/release


