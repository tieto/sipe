To enable experimental voice support in SIPE (on non-Windows platforms only):

- apply patches in this directory to libnice and libpurple
- rebuild libgstfarsight with changed libnice headers
- compile SIPE source, check that voice support is enabled in configure output
- when making a call with Office Communicator 2007 R2 peer, change to peer's
  registry is needed to allow unencrypted media transfer, use the attached .reg file
- now you can try to make a voice call 

STATUS OF PATCHES IN UPSTREAM
=============================

purple_mime_document_parsen.patch
	- reported to libpurple developers as ticket http://developer.pidgin.im/ticket/11598

purple_media_get_active_candidates.patch
	- reported to libpurple developers as ticket http://developer.pidgin.im/ticket/11830
	- should be included in version 2.8.0
	
libnice-Compatibility-with-OC2007-R2.patch
	- reported upstream https://bugs.freedesktop.org/show_bug.cgi?id=28215


Biggest show stopper now is a lack of SRTP (encrypted transfer) in Farsight library,
requiring Office Communicator users to change their registry settings as a
workaround is unacceptable. According to FS website, someone is working on
this, but no results are available so far.   
