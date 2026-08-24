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
recon:
semgrep:
vsftpd:           base-alpine


common:
	@mkdir -p ./common
	@if [ -f "$$HOME/.bashrc" ]; then cp "$$HOME/.bashrc" ./common/bashrc; \
	 else echo "no ~/.bashrc — using common/bashrc.default"; cp ./common/bashrc.default ./common/bashrc; fi
	@if [ -f "$$HOME/.config/tmux/tmux.conf" ]; then cp "$$HOME/.config/tmux/tmux.conf" ./common/tmux.conf; \
	 else echo "no ~/.config/tmux/tmux.conf — using common/tmux.conf.default"; cp ./common/tmux.conf.default ./common/tmux.conf; fi


$(IMAGES): common
	$(DOCKER_CMD) build -t skw/$@:latest -f $@/Dockerfile .


list:
	@echo $(IMAGES)


clean:
	@$(DOCKER_CMD) system prune -a -f
	@$(DOCKER_CMD) volume prune -a -f


.PHONY: all common $(IMAGES) list clean
