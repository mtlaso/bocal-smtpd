# bocal-smtpd

[![Test, Format, Build, Push to GHCR, and Deploy to VPS](https://github.com/mtlaso/bocal-smtpd/actions/workflows/deploy.yml/badge.svg)](https://github.com/mtlaso/bocal-smtpd/actions/workflows/deploy.yml)

Serveur smtp pour la fonctionnalité de newsletters de [bocal.fyi](https://www.bocal.fyi).

## Tests (local)

`make bootsrap-tests`

## Test local

1. Lancer les tests pour générer les certificats/configuration nécessaire pour utiliser ce projet localement : `make bootstrap-tests`

2. Script pour tester l'envoi de courriels localement :

```sh
swaks \
  --server 127.0.0.1:465 \
  --to xxx@bocalusermail.fyi \
  --from alice@example.com \
  --tls \
  --tls-optional \
  --data @email-data.eml
```

3. Fichier `email-data.eml` :

```
From: Alice <alice@eFrom: danny@dnncrye.dev
Content-Type: text/plain;
	charset=us-ascii
Content-Transfer-Encoding: 7bit
Mime-Version: 1.0 (Mac OS X Mail 16.0 \(3853.100.6.1.1\))
Subject: Allo
X-Universally-Unique-Identifier: C293342A-8D8D-4251-B417-BD55363D2704
Message-Id: <140AF103-B645-47C4-96EE-173B48116282@dnncrye.dev>
Date: Sat, 21 Jun 2025 03:49:34 -0400
To: danny@dnncrye.dev

Allo
```

3. Ajuster TEMPORAIREMENT la ligne de connection de la base de donnée dans `docker-compose.dev.yml` :

```yml
# ...
    environment:
    # ...
      - DATABASE_URL=postgres://admin:root@host.docker.internal:5432/bocal
     extra_hosts:
      - "host.docker.internal:host-gateway"
```

(avant de pousser, remettre les valeurs initiales dans le fichier `docker-compose.dev.yml`)

Voir les logs : `docker-compose -f docker-compose.dev.yml logs`
