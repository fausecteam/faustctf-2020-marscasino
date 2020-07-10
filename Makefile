SERVICE := marscasino
DESTDIR ?= dist_root
SERVICEDIR ?= /srv/$(SERVICE)

.PHONY: install clean

install:
	install -d -m 755                                    $(DESTDIR)/etc/uwsgi/apps-enabled/
	install -m 444 setup/uwsgi/marscasino.ini    		 $(DESTDIR)/etc/uwsgi/apps-enabled/
	install -d -m 755                                    $(DESTDIR)/etc/nginx/sites-enabled/
	install -m 444 setup/nginx/marscasino.conf 		  	 $(DESTDIR)/etc/nginx/sites-enabled/
	install -d -m 755                                    $(DESTDIR)$(SERVICEDIR)/
	install -m 555 setup/setup.sh 					  	 $(DESTDIR)$(SERVICEDIR)/
	install -m 644 src/app.py                        	 $(DESTDIR)$(SERVICEDIR)/
	install -d -m 755                                    $(DESTDIR)$(SERVICEDIR)/static/
	install -m 644 src/static/*                      	 $(DESTDIR)$(SERVICEDIR)/static/
	install -d -m 755                                    $(DESTDIR)$(SERVICEDIR)/templates/
	install -m 644 src/templates/*                   	 $(DESTDIR)$(SERVICEDIR)/templates/
	install -m 444 setup/postgres/database.sql			 $(DESTDIR)$(SERVICEDIR)/
	install -d -m 755 									 $(DESTDIR)/etc/systemd/system/
	install -m 444 setup/systemd/marscasino-db-setup.service $(DESTDIR)/etc/systemd/system/

clean:
	find . -name __pycache__ -exec rm -rf {} +
	find . -name '*.pyc' -delete

