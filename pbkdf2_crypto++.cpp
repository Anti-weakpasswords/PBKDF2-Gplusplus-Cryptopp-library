
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/pwdbased.h>

// MD5 is Weak!  Allow weakness ONLY if you need PBKDF2_HMAC_MD5
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>

#include <getopt.h>
#include <iostream>
#include <string>
// locale includes for tolower()
#include <locale>

using namespace std;
using namespace CryptoPP;


#define MD5_cryptopp           100
#define SHA_1_cryptopp         2100
#define SHA_224_cryptopp       2200
#define SHA_256_cryptopp       2300
#define SHA_384_cryptopp       2400
#define SHA_512_cryptopp       2500

// Binary printing courtesy https://stackoverflow.com/questions/111928/is-there-a-printf-converter-to-print-in-binary-format
#define BYTETOBINARYPATTERN "%d%d%d%d%d%d%d%d"
#define BYTETOBINARY(byte)  \
  (byte & 0x80 ? 1 : 0), \
  (byte & 0x40 ? 1 : 0), \
  (byte & 0x20 ? 1 : 0), \
  (byte & 0x10 ? 1 : 0), \
  (byte & 0x08 ? 1 : 0), \
  (byte & 0x04 ? 1 : 0), \
  (byte & 0x02 ? 1 : 0), \
  (byte & 0x01 ? 1 : 0) 


string PBKDF2_HMAC_SHA_512_string(string pass, string salt, uint iterations, uint outputBytes)
{
  SecByteBlock result(outputBytes);
	string hexResult;

	PKCS5_PBKDF2_HMAC<SHA512> pbkdf;

	pbkdf.DeriveKey(result, result.size(),0x00,(byte *) pass.data(), pass.size(),(byte *) salt.data(), salt.size(),iterations);

	ArraySource resultEncoder(result,result.size(), true, new HexEncoder(new StringSink(hexResult)));

  return hexResult;

}

string PBKDF2_HMAC_SHA_384_string(string pass, string salt, uint iterations, uint outputBytes)
{
  SecByteBlock result(outputBytes);
	string hexResult;

	PKCS5_PBKDF2_HMAC<SHA384> pbkdf;

	pbkdf.DeriveKey(result, result.size(),0x00,(byte *) pass.data(), pass.size(),(byte *) salt.data(), salt.size(),iterations);

	ArraySource resultEncoder(result,result.size(), true, new HexEncoder(new StringSink(hexResult)));

  return hexResult;

}

string PBKDF2_HMAC_SHA_256_string(string pass, string salt, uint iterations, uint outputBytes)
{
  SecByteBlock result(outputBytes);
	string hexResult;

	PKCS5_PBKDF2_HMAC<SHA256> pbkdf;

	pbkdf.DeriveKey(result, result.size(),0x00,(byte *) pass.data(), pass.size(),(byte *) salt.data(), salt.size(),iterations);

	ArraySource resultEncoder(result,result.size(), true, new HexEncoder(new StringSink(hexResult)));

  return hexResult;

}


string PBKDF2_HMAC_SHA_224_string(string pass, string salt, uint iterations, uint outputBytes)
{
  SecByteBlock result(outputBytes);
	string hexResult;

	PKCS5_PBKDF2_HMAC<SHA224> pbkdf;

	pbkdf.DeriveKey(result, result.size(),0x00,(byte *) pass.data(), pass.size(),(byte *) salt.data(), salt.size(),iterations);

	ArraySource resultEncoder(result,result.size(), true, new HexEncoder(new StringSink(hexResult)));

  return hexResult;

}

string PBKDF2_HMAC_SHA_1_string(string pass, string salt, uint iterations, uint outputBytes)
{
  SecByteBlock result(outputBytes);
	string hexResult;

	PKCS5_PBKDF2_HMAC<SHA1> pbkdf;

	pbkdf.DeriveKey(result, result.size(),0x00,(byte *) pass.data(), pass.size(),(byte *) salt.data(), salt.size(),iterations);

	ArraySource resultEncoder(result,result.size(), true, new HexEncoder(new StringSink(hexResult)));

  return hexResult;

}

string PBKDF2_HMAC_MD5_string(string pass, string salt, uint iterations, uint outputBytes)
{
  SecByteBlock result(outputBytes);
	string hexResult;

	PKCS5_PBKDF2_HMAC<Weak::MD5> pbkdf;

	pbkdf.DeriveKey(result, result.size(),0x00,(byte *) pass.data(), pass.size(),(byte *) salt.data(), salt.size(),iterations);

	ArraySource resultEncoder(result,result.size(), true, new HexEncoder(new StringSink(hexResult)));

  return hexResult;

}


int main(int argc, char ** argv)
{
  std::string pass, salt, hexResult, expected;
  int iterations = 0, outputBytes = 0, algo = 0, c;
  byte verbose = 0, help = 0, interactive = 0;
  std::locale loc;

  opterr = 0;

  while ((c = getopt (argc, argv, "nhva:p:P:s:S:i:o:O:e:")) != -1)
    switch (c)
      {
      case 'a':
        if (strcmp(optarg,"SHA-512")==0)
          {
            algo = SHA_512_cryptopp;
          }
        else if (strcmp(optarg,"SHA-384")==0)
          {
            algo = SHA_384_cryptopp;
          }
        else if (strcmp(optarg,"SHA-256")==0)
          {
            algo = SHA_256_cryptopp;
          }
        else if (strcmp(optarg,"SHA-224")==0)
          {
            algo = SHA_224_cryptopp;
          }
        else if (strcmp(optarg,"SHA-1")==0)
          {
            algo = SHA_1_cryptopp;
          }
        else if (strcmp(optarg,"MD5")==0)
          {
            algo = MD5_cryptopp;
          }
        else
          {
            cout << "ERROR: -a argument '" << optarg << "'  unknown." << std::endl;
            return 4;
          }
        break;
      case 'p':
        pass = optarg;
        break;
      case 's':
        salt = optarg;
        break;
      case 'i':
        iterations = atoi(optarg);
        break;
      case 'o':
        outputBytes = atoi(optarg);
        break;
      case 'v':
        verbose = 1;
        break;
      case 'h':
        help = 1;
        break;
      case 'n':
        interactive = 1;
        break;
      case 'e':
        expected = optarg;
        break;
      case '?':
        cout << "Case ?";
       if (optopt == 'c')
         std::cout << "Option - " << optopt << " requires an argument." << std::endl;
       else if (isprint (optopt))
         std::cout << "Unknown option '" << optopt << "'" << std::endl;
       else
         std::cout << "Unknown option character '" << optopt << "'" << std::endl;
       return 1;
      default:
        cout << "Case default" << std::endl;
        break;
      }
      
  if (help)
    {
    std::cout << "Compiled with Crypto++ version " << CRYPTOPP_VERSION;
    if (CRYPTOPP_BOOL_X64)
      {
      std::cout << " x64 ";
      };
    if (CRYPTOPP_BOOL_X86)
      {
      std::cout << " x86 ";
      };
    std::cout << std::endl << "Running with Crypto++ version ???" << std::endl;

    cout << "Example: " << argv[0] << " -a SHA-512 -p password -s salt -i 131072 -o 64" << std::endl;
    cout << "\nOptions: " << std::endl;
    cout << "  -h                 help" << std::endl;
    cout << "  -v                 Verbose" << std::endl;
    cout << "  -a algo            algorithm, valid values SHA-512|SHA-384|SHA-256|SHA-224|SHA-1|MD5   Note that in particular, SHA-384 and SHA-512 use 64-bit operations which as of 2014 penalize GPU's (attackers) much, much more than CPU's (you).  Use one of these two if at all possible." << std::endl;
    cout << "  -p password        Password to hash" << std::endl;
    cout << "  -P passwordfmt     NOT YET IMPLEMENTED - always string" << std::endl;
    cout << "  -s salt            Salt for the hash.  Should be long and cryptographically random." << std::endl;
    cout << "  -S saltfmt         NOT YET IMPLEMENTED - always string" << std::endl;
    cout << "  -i iterations      Number of iterations, as high as you can handle the delay for, at least 16384 recommended." << std::endl;
    cout << "  -o bytes           Number of bytes of output; for password hashing, keep less than or equal to native hash size (MD5 <=16, SHA-1 <=20, SHA-256 <=32, SHA-512 <=64)" << std::endl;
    cout << "  -O outputfmt       Output format NOT YET IMPLEMENTED - always HEX (lowercase)" << std::endl;
    cout << "  -e hash            Expected hash (in the same format as outputfmt) results in output of 0 <actual> <expected> = different, 1 = same NOT YET IMPLEMENTED" << std::endl;
    cout << "  -n                 Interactive mode - NEEDS ONLY -a algo command line argument - asks for password, salt, iterations, outputBytes" << std::endl;
    };


  if (interactive)
    {
    std::cout << std::endl << "Enter pass: ";
    std::getline(std::cin,pass);
    std::cout << "Enter salt: ";
    std::getline(std::cin,salt);
    std::cout << "Enter iterations: ";
    std::cin >> iterations;
    std::cout << "Enter outputBytes: ";
    std::cin >> outputBytes;
    //  std::cout << "Enter expected result hash (lower case hex): ";
    //  std::cin >> expected;
    };


  if (verbose)
    {
    cout << "Interpreted arguments: algo " << algo << " password " << pass << " salt " << salt << " iterations " << iterations << " outputbytes " << outputBytes << std::endl << std::endl;
    }

  if (algo <= 0)
    {
    cout << "You must select a known algorithm identifier." << std::endl;
    return 10;
    }

  if (iterations <= 0)
    {
    cout << "You must select at least one iteration (and preferably tens of thousands or (much) more." << std::endl;
    return 11;
    }

  if (outputBytes <= 0)
    {
    cout << "You must select at least one byte of output length." << std::endl;
    return 12;
    }


  switch (algo)
    {
    case SHA_512_cryptopp:
      if (verbose && outputBytes > 64)
      {
        cout << "WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function." << std::endl;
      }
      hexResult = PBKDF2_HMAC_SHA_512_string(pass, salt, iterations, outputBytes);
      break;
    case SHA_384_cryptopp:
      if (verbose && outputBytes > 48)
      {
        cout << "WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function." << std::endl;
      }
      hexResult = PBKDF2_HMAC_SHA_384_string(pass, salt, iterations, outputBytes);
      break;
    case SHA_256_cryptopp:
      if (verbose && outputBytes > 32)
      {
        cout << "WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function." << std::endl;
      }
      hexResult = PBKDF2_HMAC_SHA_256_string(pass, salt, iterations, outputBytes);
      break;
    case SHA_224_cryptopp:
      if (verbose && outputBytes > 28)
      {
        cout << "WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function." << std::endl;
      }
      hexResult = PBKDF2_HMAC_SHA_224_string(pass, salt, iterations, outputBytes);
      break;
    case SHA_1_cryptopp:
      if (verbose && outputBytes > 20)
      {
        cout << "WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function." << std::endl;
      }
      hexResult = PBKDF2_HMAC_SHA_1_string(pass, salt, iterations, outputBytes);
      break;
    case MD5_cryptopp:
      if (verbose && outputBytes > 16)
      {
        cout << "WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function." << std::endl;
      }
      hexResult = PBKDF2_HMAC_MD5_string(pass, salt, iterations, outputBytes);
      break;
    default:
      cout << "Invalid algorithm choice.  Internal value : " << algo << std::endl;
      return 2;
    }

  // lowercase it
  for (std::string::size_type i=0; i<hexResult.length(); ++i)
    hexResult[i] = std::tolower(hexResult[i],loc);

  if (expected.size() < 1)
    {
    // Normal output
    cout << hexResult << std::endl;
    }
  else 
    {
    // Did it match or not?
    if (expected.compare(hexResult)==0)
      {
      cout << "1" << std::endl;
      }
    else
      {
      cout << "0     " << hexResult << " " << expected << std::endl;
      }
    }





  /*
  If you wanted to return the hex values of the salt, this is a way to do that:
  SecByteBlock saltSBB(salt.size());
  saltSBB.Assign((unsigned char *)salt.data(),salt.size());
	string hexsalt;
	ArraySource saltEncoder(saltSBB,saltSBB.size(), true, new HexEncoder(new StringSink(hexsalt)));
  */


  return 0;
}
