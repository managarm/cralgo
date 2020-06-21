#pragma once

#include <cralgo/helpers.hpp>

namespace cralgo {

struct aes_secret_key {
	~aes_secret_key() {
		secure_scrub_memory(this, sizeof(aes_secret_key));
	}

	uint32_t words[60];
};

void aes256_key_schedule(const uint8_t key[],
		aes_secret_key *ek, aes_secret_key *dk);

void aes256_encrypt(const uint8_t in[], uint8_t out[], size_t blocks,
		aes_secret_key *ek);

void aes256_decrypt(const uint8_t in[], uint8_t out[], size_t blocks,
		aes_secret_key *dk);

} // namespace cralgo
