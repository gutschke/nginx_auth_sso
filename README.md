nginx_auth_sso
==============

Simple HTML authentication script for nginx (requires LUA)


Installation instructions
-------------------------

Copy all the files from this folder to /usr/share/nginx/auth

Add the following line to your nginx configuration to enable
authentication support for a given server:

    include /usr/share/nginx/auth/init-auth.conf;

    server {
      ...
      include /usr/share/nginx/auth/auth.conf;
      ...
    }

For each location that should be protected by the authentication script,
add the following lines:

    location ... {
      ...
      set $sso_realm "REALM";
      include /usr/share/nginx/auth/sso-enabled;
      ...
    }

Make sure you pick a unique value for the realm. Typically, you should
probably base it on the name of the location.

Copy sso-auth.example to /etc/sso-auth. Create new entries for your
users and for the realm that you defined. You can use the script in
"make password" to help create the password hashes.

Restart your nginx server.


Security Considerations
-----------------------

While the code goes to some trouble to avoid the most obvious attack
vectors, the code should not be used to protect high-value targets,
unless you independently audit it first.

Furthermore, if at all possible, all content that is protected by this
SSO implementation should always enforce HTTPS encryption.

Unencrypted traffic opens up a variety of different attack vectors.

Ideally, the contents of the /etc/sso-auth file must remain protected
from other users and other programs.  Depending on how nginx is
configured, this might not actually be possible (e.g. all CGI and LUA
scripts often run with the same permissions and can thus access
/etc/sso-auth; they also typically have access to server variables
such as the signing key in ngx.shared.sso:get("secret")).

If this data cannot effectively be protected, the security of the SSO
code is significantly weakened, although SSL encryption can mitigate
some but not all of the problems.

A dedicated secure SSO proxy server is probably the best solution. But
if SSO cannot be moved to a dedicated server, at the very least, you
should change the permissions on /etc/sso-auth so that the file is
read-only and only accessible by the www-data group.


Algorithms
----------

For each account, we generate some random $salt and then store it
together with a password hash that is computed as:

    password_entry := HASH(HMAC($password, $salt))

When a user tries to log in, we provide the browser with the $salt
value and with a signed timestamp that serves as a $challenge; the
$sso_secret signing key is an arbitrary random string and
automatically generated when nginx starts:

    challenge := HMAC($current_time, $sso_secret)

The browser then sends the following response to the server:

    response := HMAC($password, $salt) + HMAC(HASH(HMAC($password, $salt)), $challenge)

In order to authenticate the user, the server verifies that the
following condition holds:

        HASH($response - HMAC($password_entry, $challenge)) == $password_entry
    <=> HASH(HMAC($password, $salt) + HMAC(HASH(HMAC($password, $salt)), $challenge)
                                    - HMAC(HASH(HMAC($password, $salt)), $challenge)) ==
        HASH(HMAC($password, $salt))
    <=> HASH(HMAC($password, $salt)) == HASH(HMAC($password, $salt))

This makes sure that the server never needs access to the plain test
password, nor does it have access to a password-equivalent value.

Furthermore, the client never sends a password or a password-equivalent
value back to the server.

A passive observer would not be able to corrupt this protocol. On the
other hand, protection against active MitM attackers is not afforded by
this approach. That's where SSL encryption would help.

When a user has been authenticated, the server returns a signed token
that provides access to its services.

   token := [ ( $current_time, $realm ), ... ]
   signed_token := HMAC($token, $sso_secret)

The obvious security implications are that a) anybody with access to
$sso_secret can issue arbitrary signed tokens; and b) a passive observer
can steal the signed token and take over the authenticated session.

In order to reduce the risk from issue #a, it is important to secure the
nginx server, restrict permissions to its configuration files, and limit
who can run scripts (e.g. CGI or LUA).

Issue #b can be addressed by encrypting all authenticated sessions with
SSL.

When logging in over SSL, the token will be stored as a secure cookie.
Furthermore, it is always stored as a HttpOnly cookie.

All cryptographic operations use SHA-1 as the hash function. This is not
ideal as the algorithm is starting to get old and has a couple of known
weaknesses; but it is the only algorithm that is available to LUA at
this time. For most users, the weaknesses in the cryptographic algorithm
will have limited practical consequences, though.
