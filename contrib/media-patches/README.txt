To enable voice support in SIPE (only on platforms where libpurple supports
voice & video):

- pidgin >= 2.8.0, libnice >= 0.1.0 and farsight2 >= 0.0.26 are required
- compile SIPE source, check that voice support is enabled in configure output
- If you get errors on incompatible encryption levels when making a call, change
  to peer's registry is needed to allow unencrypted media transfer; use the
  attached .reg file. Encryption can be also already set as optional, depending
  on your domain policy configuration, in this case registry change is not needed. 
- now you can try to make a voice call 

Biggest show stopper now is a lack of SRTP (encrypted transfer) in Farsight library,
requiring Office Communicator users to change their registry settings as a
workaround is unacceptable. According to FS website, someone is working on
this, but no results are available so far. In some environments unencrypted
calls can be allowed by domain policy, so not all users are affected.
