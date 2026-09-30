# `continuum-keycloak-spi`

Extensions SPI Keycloak (plan §4.5.2). Le backend ne voit jamais un mot de passe : Keycloak est
un **service d'authentification séparé** (`continuum-auth`), le backend est un *resource server* OAuth2.

## Contraintes de build

- Dépendances Keycloak en **`provided`**, à la **version exacte** de l'image (`keycloak.version` du pom).
- L'image se construit par `FROM quay.io/keycloak/keycloak:<version>` + copie du jar dans
  `/opt/keycloak/providers/` + `kc.sh build` (voir `../continuum-auth`).

## Extensions prévues (§4.5.2)

| Type | Fournisseur | Rôle |
|---|---|---|
| Authenticator | `AdminNetworkAuthenticator` | Exige réseau d'administration + clé FIDO2 pour le client `continuum-admin` |
| Theme | `continuum-theme` | Page de connexion aux couleurs du tenant (mêmes tokens `--ct-*` que les frontends, §1.6.3), FR/AR/EN + RTL |

> Les fournisseurs se déclarent dans `src/main/resources/META-INF/services/`.
