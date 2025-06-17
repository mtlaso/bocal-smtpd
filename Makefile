test-build:
	go test ./tests/ -v --build-bocal-smtpd=true
test:
	go test ./tests/ -v
test-emailparser:
	go test ./emailparser/ -v
fmt:
	golangci-lint fmt -c=golangci.yml
