After upgrading to Mavericks SIPE always fails with "Read Error"
================================================================

Apple enabled SSL BEAST mitigation by default in Mac OS X 10.9 (Mavericks):

   <https://community.qualys.com/blogs/securitylabs/2013/10/31/apple-enabled-beast-mitigations-in-os-x-109-mavericks>

This causes an interoperability problem for SIPE, because there are are still
Microsoft servers out there whose SSL stacks drop connections when the SSL
stack on the client implements the standard 1/N-1 packet split to mitigate
against SSL BEAST attacks:

    <http://sourceforge.net/p/sipe/wiki/Frequently%20Asked%20Questions/#connection-problems>

There is a system preference option in Mac OS X 10.9 to disable SSL BEAST
mitigation for all SSL connections:

   $ sudo defaults write /Library/Preferences/com.apple.security SSLWriteSplit -integer 0

Unfortnately there is a bug in Mac OS X 10.9 which causes the SSL stack to
ignore this setting:

   <rdar://15432593>

The only known working fix is to patch the SSL CDSA module in the Adium source
tree to disable the SSL BEAST mitigation for all SSL connection create by the
"prpl-sipe" plugin. Download the Adium source code, unpack it and then apply
the patch to it:

   $ cd adium-1.5.8
   $ patch -p1 </path/to/sipe/source/contrib/adium-patches/adium-1.5.8-disable-ssl-mitigation.patch

Then follow the standard Adium instruction to build it.


Detailed discussion about the SSL BEAST mitigation problem on Mac OS X 10.9:

   http://sourceforge.net/p/sipe/bugs/216
