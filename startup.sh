#!/bin/bash

# Mettre à jour et installer les dépendances système pour WeasyPrint
apt-get update && apt-get install -y libpango-1.0-0 libpangoft2-1.0-0 libgobject-2.0-0

# Lancer l'application avec Gunicorn (la même commande qu'avant)
gunicorn --bind=0.0.0.0 --timeout 600 app:app