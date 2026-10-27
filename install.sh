#!/bin/bash
set -e

TITLE="All Seeing Eye - Installation"
cd "$(dirname "$0")"

WRITE_ENV=yes
if [ -f .env ] && ! whiptail --title "$TITLE" --yesno "A .env file already exists.\n\nOverwrite it? (No = keep the existing one)" 10 60; then
    WRITE_ENV=no
fi

if [ "$WRITE_ENV" = yes ]; then
    DB_USER=$(whiptail --title "$TITLE" --inputbox "Database user:" 10 60 "ase" 3>&1 1>&2 2>&3)
    DB_NAME=$(whiptail --title "$TITLE" --inputbox "Database name:" 10 60 "allseeingeye" 3>&1 1>&2 2>&3)
    PGADMIN_EMAIL=$(whiptail --title "$TITLE" --inputbox "pgAdmin email:" 10 60 "admin@example.com" 3>&1 1>&2 2>&3)
    PGADMIN_PASSWORD=$(whiptail --title "$TITLE" --passwordbox "pgAdmin password (leave empty to generate one)" 10 60 3>&1 1>&2 2>&3)

    [ -z "$PGADMIN_PASSWORD" ] && PGADMIN_PASSWORD=$(openssl rand -base64 18 | tr -d '/+=')
    cat > .env <<EOF
POSTGRES_USER=$DB_USER
POSTGRES_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=')
POSTGRES_DB=$DB_NAME
PGADMIN_DEFAULT_EMAIL=$PGADMIN_EMAIL
PGADMIN_DEFAULT_PASSWORD=$PGADMIN_PASSWORD
WEBUI_SECRET_KEY=$(openssl rand -hex 32)
EOF
    chmod 600 .env
fi

docker compose up -d --build

whiptail --title "$TITLE" --msgbox "Installation complete!\n\nDashboard: http://localhost:8000\npgAdmin: http://localhost:8080\n\nCredentials are stored in the .env file." 14 60