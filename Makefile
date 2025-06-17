###########################
#### smtp server tests ####
###########################
test-build:
	go test ./tests/ -v --build-bocal-smtpd=true
test:
	go test ./tests/ -v

############################
#### email parser tests ####
############################
test-emailparser:
	go test ./emailparser/ -v

bootstrap-tests:
	make test-build
	make test-emailparser

fmt:
	golangci-lint fmt -c=golangci.yml
