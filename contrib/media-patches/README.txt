Dependencies needed to enable voice in SIPE at compile time (only on platforms
where libpurple supports voice & video):

- minimum: pidgin >= 2.8.0, libnice >= 0.1.0, farsight2 >= 0.0.26
- recommended: pidgin 3.0, libnice >= 0.1.13, farstream >= 0.2.7

SRTP is supported since Pidgin 3.0. With older versions, if you get errors on
incompatible encryption levels when making a call, change to peer's registry
is needed to allow unencrypted media transfer; use the .reg file in this
directory.
