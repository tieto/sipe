To enable experimental voice support in SIPE (only on platforms where libpurple
supports voice & video):

- for compatibility with OC 2007, OC 2007 R2 and MS Lync 2010 RC, apply these
  patches to libnice, libpurple and farsight:
	- purple_mime_document_parsen.patch
	- purple_media_get_active_candidates.patch
	- purple_media_fs2_dispose.patch
	- pidgin_media_remove_request_timeout_cb_on_dispose.patch (optional)
	- libnice01-Compatibility-with-MSOC-2007-R2.patch
	- libnice02-Compatibility-with-MSOC-2007.patch
	- libnice03-MS-TURN-support-for-Microsoft-Office-Communicator.patch
	- farsight-Compatibility-with-OC2007.patch
- compile SIPE source, check that voice support is enabled in configure output
- If you get errors on incompatible encryption levels when making a call, change
  to peer's registry is needed to allow unencrypted media transfer; use the
  attached .reg file. Encryption can be also already set as optional, depending
  on your domain policy configuration, in this case registry change is not needed. 
- now you can try to make a voice call 

STATUS OF PATCHES IN UPSTREAM
=============================

purple_mime_document_parsen.patch
	- reported to libpurple developers as ticket http://developer.pidgin.im/ticket/11598

purple_media_get_active_candidates.patch
	- reported to libpurple developers as ticket http://developer.pidgin.im/ticket/11830
	- should be included in version 2.8.0

purple_media_fs2_dispose.patch
	- reported to libpurple developers as ticket http://developer.pidgin.im/ticket/12758

pidgin_media_remove_request_timeout_cb_on_dispose.patch
	- reported to libpurple developers as ticket http://developer.pidgin.im/ticket/12806

libnice01-Compatibility-with-MSOC-2007-R2.patch
	- reported upstream https://bugs.freedesktop.org/show_bug.cgi?id=28215
	- accepted for release libnice 0.0.14

libnice02-Compatibility-with-MSOC-2007.patch
	- reported upstream http://lists.freedesktop.org/archives/nice/2010-August/000365.html
	- accepted for release libnice 0.0.14

libnice03-MS-TURN-support-for-Microsoft-Office-Communicator.patch
	- accepted for release libnice 0.0.14

farsight-Compatibility-with-OC2007.patch
	- reported upstream http://lists.freedesktop.org/archives/nice/2010-August/000365.html
	- should be included in 0.0.22 release


Biggest show stopper now is a lack of SRTP (encrypted transfer) in Farsight library,
requiring Office Communicator users to change their registry settings as a
workaround is unacceptable. According to FS website, someone is working on
this, but no results are available so far. UPDATE: in some environments unencrypted
calls can be allowed by domain policy, so not all users are affected.
