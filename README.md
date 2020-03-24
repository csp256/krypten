# krypten
Encryption as painlessly as possible.

## Usage

			std::string plaintext = "The man in black fled across the desert, and the gunslinger followed.";
      using namespace krypten;
			auto key = Krypten::random_key();
			auto krypten = Krypten{ key };
			auto ciphertext = krypten.encrypt(plaintext);
			auto deciphered = krypten.decrypt(ciphertext);
      assert(plaintext == deciphered);

## Technical

* Implements AES 256 in CTR mode. 
* Prepends IV to ciphertext. 
* Uses CSPRNG for random numbers. 
* Cross platform
