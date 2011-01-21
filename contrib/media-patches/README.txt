To enable experimental voice support in SIPE (only on platforms where libpurple
supports voice & video):

- libnice >= 0.1.0 and farsight2 >= 0.0.23 are required
- source tree of Pidgin 2.7.8 or higher is required and following patches must
  be applied:
	- purple_media_get_active_candidates.patch
	- purple_media_fs2_dispose.patch
	- purple_SDES.patch
- compile SIPE source, check that voice support is enabled in configure output
- If you get errors on incompatible encryption levels when making a call, change
  to peer's registry is needed to allow unencrypted media transfer; use the
  attached .reg file. Encryption can be also already set as optional, depending
  on your domain policy configuration, in this case registry change is not needed. 
- now you can try to make a voice call 

STATUS OF PATCHES IN UPSTREAM
=============================

purple_media_get_active_candidates.patch
	- reported to libpurple developers as ticket http://developer.pidgin.im/ticket/11830
	- commited for future 2.8.0 release

purple_media_fs2_dispose.patch
	- reported to libpurple developers as ticket http://developer.pidgin.im/ticket/12758
	- commited for future 2.7.10 release

Biggest show stopper now is a lack of SRTP (encrypted transfer) in Farsight library,
requiring Office Communicator users to change their registry settings as a
workaround is unacceptable. According to FS website, someone is working on
this, but no results are available so far. UPDATE: in some environments unencrypted
calls can be allowed by domain policy, so not all users are affected.
