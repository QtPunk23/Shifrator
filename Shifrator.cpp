#include <iostream>
#include <fstream>
#include <cstdint>
#include <vector>
#include <random>
#include <bitset>
#include <array>
#include <algorithm>
#include <filesystem>

constexpr size_t BLOCK_SIZE = 64;
constexpr size_t SUBBLOCK_SIZE = 32;
constexpr size_t KEY_SIZE = 64;
constexpr size_t NUM_ROUNDS = 8;

//генартор рандомного 64-битного ключа
uint64_t generate_random_key() {
    std::random_device rd;
    std::mt19937_64 eng(rd());
    std::uniform_int_distribution<uint64_t> distr;
    return distr(eng);
}

// Функция для выполнения циклического сдвига вправо для 64-разрядного целого числа
uint64_t circular_right_shift(uint64_t key, unsigned n) {
    return (key >> n) | (key << (BLOCK_SIZE - n));
}

// Функция для выполнения кругового сдвига влево для 32-разрядного целого числа
uint32_t circular_left_shift(uint32_t block, unsigned n) {
    return (block << n) | (block >> (SUBBLOCK_SIZE - n));
}

// Функция для генерации универсальных ключей
std::array<uint32_t, NUM_ROUNDS> generate_round_keys(uint64_t master_key) {
    std::array<uint32_t, NUM_ROUNDS> round_keys;
    for (size_t i = 0; i < NUM_ROUNDS; ++i) {
        round_keys[i] = circular_right_shift(master_key, i * 3) & 0xFFFFFFFF;
    }
    return round_keys;
}

// Циклическая функция F, как определено в задаче
uint32_t round_function(uint32_t L, uint32_t K) {
    return circular_left_shift(L, 9) ^ (~((circular_right_shift(K, 11) & L)));
}

// Функция сетевого шифрования Фестеля
uint64_t feistel_encrypt(uint64_t block, const std::array<uint32_t, NUM_ROUNDS>& round_keys) {
    uint32_t L = block >> SUBBLOCK_SIZE;
    uint32_t R = block & ((1ULL << SUBBLOCK_SIZE) - 1);

    for (size_t i = 0; i < NUM_ROUNDS; ++i) {
        uint32_t temp = R;
        R = L ^ round_function(R, round_keys[i]);
        L = temp;
    }

    return (uint64_t(R) << SUBBLOCK_SIZE) | L;
}

// Функция дешифрования сети Фестиля
uint64_t feistel_decrypt(uint64_t block, const std::array<uint32_t, NUM_ROUNDS>& round_keys) {
    uint32_t L = block & ((1ULL << SUBBLOCK_SIZE) - 1);
    uint32_t R = block >> SUBBLOCK_SIZE;

    for (int i = NUM_ROUNDS - 1; i >= 0; --i) {
        uint32_t temp = L;
        L = R ^ round_function(L, round_keys[i]);
        R = temp;
    }

    return (uint64_t(L) << SUBBLOCK_SIZE) | R;
}

// Вспомогательная функция для печати 64-битного блока в виде текста
void print_block_as_hex(const std::string& prefix, uint64_t block) {
    std::cout << prefix;
    for (int i = 7; i >= 0; --i) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
            << ((block >> (8 * i)) & 0xFF) << " ";
    }
    std::cout << std::dec << std::endl; // Возвращаемся к десятичному выводу для остального кода
}

// Функция для чтения из файла, шифрования данных и записи в другой файл
void process_file(const std::string& input_filename, const std::string& output_filename, uint64_t key, bool encrypt) {
    std::ifstream input_file(input_filename, std::ios::binary);
    std::ofstream output_file(output_filename, std::ios::binary);

    if (!input_file || !output_file) {
        std::cerr << "Error opening files." << std::endl;
        return;
    }

    auto round_keys = generate_round_keys(key);
    std::vector<char> buffer(BLOCK_SIZE / 8);

    while (input_file.read(buffer.data(), buffer.size()) || input_file.gcount() != 0) {
        uint64_t block;
        std::memcpy(&block, buffer.data(), input_file.gcount());

        // Если последний блок меньше 64 бит, добавляем padding
        if (input_file.gcount() < static_cast<std::streamsize>(buffer.size())) {
            std::fill(buffer.begin() + input_file.gcount(), buffer.end(), 0);
            std::memcpy(&block, buffer.data(), buffer.size());
        }

        if (encrypt) {
            print_block_as_hex("Encrypting block: ", block);
            block = feistel_encrypt(block, round_keys);
            print_block_as_hex("Encrypted block: ", block);
        }
        else {
            print_block_as_hex("Decrypting block: ", block);
            block = feistel_decrypt(block, round_keys);
            print_block_as_hex("Decrypted block: ", block);
        }

        output_file.write(reinterpret_cast<const char*>(&block), sizeof(block));
    }
}

int main() {
    uint64_t key = generate_random_key();
    std::filesystem::path input_filename =  "input.bin";
    std::filesystem::path encrypted_filename =  "encrypted.bin";
    std::filesystem::path decrypted_filename =  "decrypted.bin";

    process_file(input_filename.string(), encrypted_filename.string(), key, true);
    process_file(encrypted_filename.string(), decrypted_filename.string(), key, false);

    return 0;
}
