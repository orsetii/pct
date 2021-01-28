.PHONY: run setup

run:
	sh ./run.sh

setup:
	sudo ip tuntap add tap0 mode tap
	
