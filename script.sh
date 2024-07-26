#!/bin/bash

set -x

echo "Listar"
ls

python security_manager/manage.py makemigrations
python security_manager/manage.py migrate
python security_manager/manage.py test
python security_manager/manage.py runserver 0.0.0.0:8000

