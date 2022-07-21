##
# isos_inject
#
# @version 0.1
EXE = isos_inject

all: build check

build: inject
	@cd src && ${MAKE}
	@cp -f src/${EXE} ./
	@cp date.bak date

inject: inject.asm
	nasm -f bin $<

check:
	@cd src && ${MAKE} check

clean:
	@cd src && ${MAKE} clean
	rm -f ${EXE}

help:
	@echo "Usage:"
	@echo "  make [all]\t\tBuild and check"
	@echo "  make clean\t\tRemove all the files generated by make"
	@echo "  make check\t\tRun the clang-tidy check
	@echo "  make help\t\tDisplay this help"

.PHONY: all build check clean help

# end