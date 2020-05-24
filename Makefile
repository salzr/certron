clean:
ifneq ($(wildcard ./certron),)
	rm certron
endif

build: clean
	go build -mod=vendor -trimpath -o certron .
