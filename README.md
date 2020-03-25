# krypten
Encryption as simple as possible. Portable C++11 that just works. 

No configuration, no bloated API, no namespace pollution, no special build system, no bullshit. 

Intended to be fully secure, but if you want security guarantees use OpenSSL instead.

## Usage

      std::string plaintext = "The man in black fled across the desert, and the gunslinger followed.";
      using namespace krypten;
      auto secret_key = Krypten::random_key();
      {
            auto krypten = Krypten{ secret_key };
            auto ciphertext = krypten.encrypt(plaintext);
            Krypten::save_ciphertext("./secure.bin", ciphertext);
      }
      {
            auto krypten = Krypten{ secret_key };
            auto ciphertext = Krypten::load_ciphertext("./secure.bin");
            auto plaintext = krypten.decrypt(ciphertext);
      }
      
That's it. That's the whole API. Nothing else is supported. 

## Technical

* Implements AES 256 in CTR mode. 
* Prepends random IV to ciphertext. 
* Cryptographically secure random numbers. 

## To-Do

* Unnecessary overhead around pkcs5 proceedure
* Parallel encryption and decryption
* Decrypt only subset of plaintext
* Optimization opportunities with SIMD
* Should probably be able to take a `std::vector<T>` or `T *` + `num_bytes`.

## License

Krypten itself is in the public domain. 

CSPRNG is distributed under the Boost Software License, Version 1.0.

Snippets are taken from https://github.com/calccrypto/Encryptions which is MIT licensed. 

## Disclaimer

Use OpenSSL if you're encrypting something really important. You're on your own.
