CONTIKI = ../../contiki
APPS = serial-shell
ifndef TARGET
TARGET=sky
endif

CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"

all: sdr_shell

upload:
	make sdr_shell.upload

CONTIKI_WITH_RIME = 1
include $(CONTIKI)/Makefile.include
