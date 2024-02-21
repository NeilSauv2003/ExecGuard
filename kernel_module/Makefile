work-dir = src
module-name = main
obj-m += $(work-dir)/$(module-name).o

all:
	make -C ${KERNEL_SRC} M=$(PWD) modules

clean:
	mv compile_commands.json ..
	make -C ${KERNEL_SRC} M=$(PWD) clean
	mv ../compile_commands.json .


install: all
	@if lsmod | grep $(module-name) &> /dev/null ; then \
		echo "Module $(module-name) already loaded, attempting to replace it..."; \
		sudo rmmod $(module-name); \
	fi;
	echo "Inserting module $(module-name)..."
	sudo insmod $(work-dir)/$(module-name).ko


uninstall: clean
	sudo rmmod $(module-name)
