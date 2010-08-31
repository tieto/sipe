To enable experimental voice support in SIPE (on non-Windows platforms only):

- for compatibility with OC 2007 R2, apply these patches to libnice and libpurple:
	- purple_mime_document_parsen.patch
	- purple_media_get_active_candidates.patch
	- libnice-Compatibility-with-OC2007-R2.patch 
- compile SIPE source, check that voice support is enabled in configure output
- If you get errors on incompatible encryption levels when making a call with
  Office Communicator 2007 R2 peer, change to peer's registry is needed to allow
  unencrypted media transfer, use the attached .reg file. Encryption can be also
  already set as optional, depending on your domain policy configuration, in this
  case registry change is not needed. 
- now you can try to make a voice call 

- compatibility with OC 2007 (first release) is still being developed in SIPE,
  applying related patches to libnice and libgstfarsight has no effect for now. 

STATUS OF PATCHES IN UPSTREAM
=============================

purple_mime_document_parsen.patch
	- reported to libpurple developers as ticket http://developer.pidgin.im/ticket/11598

purple_media_get_active_candidates.patch
	- reported to libpurple developers as ticket http://developer.pidgin.im/ticket/11830
	- should be included in version 2.8.0
	
libnice-Compatibility-with-OC2007-R2.patch
	- reported upstream https://bugs.freedesktop.org/show_bug.cgi?id=28215
	- actively collaborating with libnice developers on improving the patch to
	  be acceptable for merge

libnice-Compatibility-with-OC2007.patch
	- reported upstream http://lists.freedesktop.org/archives/nice/2010-August/000365.html
	- actively collaborating with libnice developers on improving the patch to
	  be acceptable for merge

farsight-Compatibility-with-OC2007.patch
	- reported upstream http://lists.freedesktop.org/archives/nice/2010-August/000365.html
	- actively collaborating on improving the patch to be acceptable for merge


Biggest show stopper now is a lack of SRTP (encrypted transfer) in Farsight library,
requiring Office Communicator users to change their registry settings as a
workaround is unacceptable. According to FS website, someone is working on
this, but no results are available so far. UPDATE: in some environments unencrypted
calls can be allowed by domain policy, so not all users are affected.
