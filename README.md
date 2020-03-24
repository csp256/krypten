# krypten
Encryption as simple as possible.

## Usage

      std::string plaintext = "The man in black fled across the desert, and the gunslinger followed.";
      using namespace krypten;
      auto secret_key = Krypten::random_key();
      auto krypten = Krypten{ secret_key };
      auto ciphertext = krypten.encrypt(plaintext);
      auto deciphered = krypten.decrypt(ciphertext);
      assert(plaintext == deciphered);
      
That's it. That's the whole API. 

## Technical

* Implements AES 256 in CTR mode. 
* Prepends random IV to ciphertext. 
* Cryptographically secure random numbers. 
* Portable C++11.

## To-Do

* Unnecessary overhead around pkcs5 proceedure
* Parallel encryption and decryption
* Decrypt only subset of plaintext
* Optimization opportunities with SIMD

## License

Krypten itself is in the public domain. 

CSPRNG is distributed under the Boost Software License, Version 1.0.

Snippets are taken from https://github.com/calccrypto/Encryptions which is MIT licensed. 

## Disclaimer

You should probably be using OpenSSL.
