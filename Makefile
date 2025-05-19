test-build:
	go test ./tests/ -v --build-bocal-smtpd=true
test:
	go test ./tests/ -v
