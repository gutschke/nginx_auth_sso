all:

install:
	@echo "Copying files to /usr/local/openresty/nginx/auth and restarting"; \
	echo "nginx web server...";                                              \
	sudo sh -ec 'mkdir -p /usr/local/openresty/nginx/auth &&                 \
	             cp -a * /usr/local/openresty/nginx/auth/ &&                 \
	             /etc/init.d/nginx restart'

password:
	@echo "Enter account information to compute password hash";      \
	read -p "User id: " user;                                        \
	while :; do                                                      \
	  stty="`stty -g`"; trap 'stty $${stty}' INT HUP TERM QUIT EXIT; \
	  stty -echo;                                                    \
	  read -p "Password: " password; echo;                           \
	  read -p "Re-enter password: " verify; echo;                    \
	  trap - INT HUP TERM QUIT EXIT; stty $${stty};                  \
	  [ -n "$${password}" ] &&                                       \
	    [ "$${password}" = "$${verify}" ] && break;                  \
	  echo "Password error; please retry";                           \
	done;                                                            \
	read -p "Realm(s): " realms;                                     \
	salt="`dd if=/dev/urandom count=1 2>&1 |                         \
               openssl dgst -sha1 -binary      |                         \
	       base64                          |                         \
	       sed 's/\(........\).*/\1/'`";                             \
	hash="`echo -n "$${password}" |                                  \
	  openssl dgst -sha1 -hmac "$${salt}" -binary |                  \
	  openssl dgst -sha1 -binary |                                   \
	  base64`";                                                      \
	printf '%s\t%s\t%s\n' "$${user}" "$${salt}:$${hash}" "$${realms}"
