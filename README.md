nginx_auth_sso
==============

Simple HTML authentication script for nginx (requires LUA)


Installation instructions
-------------------------

Copy all the files from this folder to /usr/share/nginx/auth

Add the following line to your nginx configuration to enable
authentication support for a given server:

    server {
      ...
      set $sso_secret "SOME-ARBITRARY-RANDOM-STRING";
      include /usr/share/nginx/auth/auth.cfg;
      ...
    }

A good way to generate $sso_secret is

    dd if=/dev/urandom count=1 2>&1|sha1sum

For each location that should be protected by the authentication
script, add the following lines:

    location ... {
      ...
      set $sso_realm "REALM";
      include /usr/share/nginx/auth/sso-enabled;
      ...
    }

Make sure you pick a unique value for the realm. Typically, you
should probably base it on the name of the location.

Copy sso-auth.example to /etc/sso-auth. Create new entries for
your users and for the realm that you defined. You can use the
script in "make password" to help create the password hashes.

Restart your nginx server.


Security Considerations
-----------------------

While the code goes to some trouble to avoid the most obvious
attack vectors, the code should not be used to protect high-value
targets.

Furthermore, if at all possible, all content that is protected
by this SSO implementation should always enforce HTTPS encryption.

Encrypted traffic thwarts a lot of possible attacks.

Ideally, the $sso_secret and the contents of the /etc/sso-auth file
must remain protected from other users and other programs.
Depending on how nginx is configured, this might not actually be
possible (e.g. user's CGI scripts could gain access to these files,
even if file permission are set restrictively).

If this data cannot be protected, the security of the SSO code is
significantly weakened.
