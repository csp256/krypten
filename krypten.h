#pragma once
#include <array>
#include <string>
#include <vector>

namespace krypten {

    class Krypten {
    public:
        struct alignas(16) Block : std::array<uint32_t, 4> {};
        struct alignas(16) Key : std::array<uint8_t, 32> {};

        explicit 
        Krypten(Key const& key);

        static Key
        random_key();

        std::vector<Krypten::Block> 
        encrypt(std::string const& data) const;
        
        std::string 
        decrypt(std::vector<Krypten::Block> const& data) const;
        
        static std::vector<Krypten::Block>
        load_ciphertext(std::string const& path);

        static void
        save_ciphertext(std::string const& path, std::vector<Krypten::Block> const& in);

    private:
        void 
        increment_IV(Block& IV) const;

        Block 
        encrypt_block(Block const& DATA) const;

        std::array<Block, 15> keys;
    };

}
