IMAGES = base-alpine base-archlinux base-debian base-ubuntu ad forensic http-server java-env php-env pwn recon semgrep vsftpd
DOCKER_CMD = docker


all: $(IMAGES)
base-alpine:
base-archlinux:
base-debian:
base-ubuntu:
ad:               base-archlinux
forensic:         base-archlinux
http-server:
java-env:         base-archlinux
php-env:          base-ubuntu
pwn:              base-archlinux
recon:            base-archlinux
semgrep:
vsftpd:           base-alpine


common:
	mkdir -p ./common
	cp ~/.bashrc ./common/bashrc
	cp ~/.config/tmux/tmux.conf ./common/tmux.conf


$(IMAGES): common
	$(DOCKER_CMD) build -t skw/$@:latest -f $@/Dockerfile .


list:
	@echo $(IMAGES)


clean:
	@$(DOCKER_CMD) system prune -a -f
	@$(DOCKER_CMD) volume prune -a -f


.PHONY: all common $(IMAGES) list clean
