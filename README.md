# bocal-smtpd
[![Test, Format, Build, Push to GHCR, and Deploy to VPS](https://github.com/mtlaso/bocal-smtpd/actions/workflows/deploy.yml/badge.svg)](https://github.com/mtlaso/bocal-smtpd/actions/workflows/deploy.yml)

Serveur smtp pour la fonctionnalité de newsletters de [bocal.fyi](https://www.bocal.fyi).

## Tests (local)

1. Première exécution : `make test-build` (génère les certificats).
2. Par la suite : `make test`

## Autre

- Formatter : `make fmt` (installer golangci-lint au préalable)
