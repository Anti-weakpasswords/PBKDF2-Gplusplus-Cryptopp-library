PBKDF2-Gplusplus-Cryptopp-library
=================================

PBKDF2 using the Crypto++ library (as a compilation, so this is Boost 1.0 licensed)



To compile this code, you will need the Crypto++ library - on Debian, for instance, you could install this with "sudo apt-get install libcrypto++-dev".  Library source code is at http://www.cryptopp.com/

This code was tested compiled on Debian 7 x64 using Crypto++ 5.6.1 and g++ 4.7.2.

This version has a primitive interactive mode, which has less gaping security holes (users can't see your password, salt, iteration count, and outputBytes on their view of your command line - algorithm is still there, thoug) which can be used by "./pbkdf2 -a SHA-512 -n"
