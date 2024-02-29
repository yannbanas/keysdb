# KeysDB

KeysDB est une application de stockage clé-valeur qui fournit une interface simple pour stocker, récupérer et supprimer des données en utilisant des commandes TCP. Cette application est conçue pour être conviviale et peut être utilisée dans divers scénarios, notamment le stockage de configurations, la gestion de sessions utilisateur, et bien plus encore.

## Installation

1. Clonez le dépôt :

```
git clone https://github.com/votre-nom-utilisateur/keysdb.git
cd keysdb
```

2. Build package from source :

```
python setup.py bdist_wheel
```

## Utilisation

### Démarrage du serveur

Pour démarrer le serveur KeysDB, exécutez la commande suivante :

```
python examples/server.py
```

### Exécution de commandes depuis le client

Pour interagir avec le serveur KeysDB, vous pouvez utiliser le client inclus. Voici comment exécuter différentes commandes :

1. **SET**: Définir une nouvelle paire clé-valeur dans le magasin de clés.

```
SET mykey Hello string 60
```

les types valide sont: ***['string', 'integer', 'list', 'hash']***

2. **GET**: Récupérer la valeur associée à une clé spécifique dans le magasin de clés.

```
GET mykey
```

3. **DELETE**: Supprimer une clé spécifique et sa valeur associée du magasin de clés.

```
DELETE mykey
```

4. **CONTAINS**: Vérifier si une clé spécifique existe dans le magasin de clés.

```
CONTAINS mykey
```

5. **ITER**: Afficher toutes les clés présentes dans le magasin de clés.

```
ITER
```

6. **HSET**: Définir une nouvelle paire clé-valeur dans un hachage spécifique dans le magasin de clés.

```
HSET myhash field1 value1 60
```

7. **HGET**: Récupérer la valeur associée à un champ spécifique dans un hachage spécifique dans le magasin de clés.

```
HGET myhash field1
```

8. **LEN**: Récupérer le nombre total de paires clé-valeur dans le magasin de clés.

```
LEN
```

9. **QUIT**: Déconnecter proprement le client du serveur.

```
QUIT
```

## Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.