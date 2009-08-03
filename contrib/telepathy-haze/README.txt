SIPE can act as Empathy/Telepathy backend if used with purple based Telepathy manager - telepathy-haze.

To make it work, the following should be done:
1) Ensure libsipe.* files reside with other purple plugins (In /usr/lib/purple-2 for Ubuntu).
2) /usr/share/telepathy/managers/haze.manager is patched with the patch provided.
3) Added sipe.profile file to /usr/share/mission-control/profiles

For configuration, combine Pidgin's Username and Login fields separated with comma to Account field like:
alice@boston.local,BOSTON\alice

WARNING:
SIPE functionality in Empathy/Telepathy is limited to two-party conversation only.
It misses the following, so barely usable:
- contact search
- multi-party chat
- user info
- send mail
