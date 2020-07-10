#!/bin/sh

su postgres -c "createuser marscasino"
su postgres -c "createdb -O marscasino marscasino"
su -s /bin/sh marscasino -c "psql -f /srv/marscasino/database.sql"

touch /srv/marscasino/setup
