#include <cralgo/helpers.hpp>

namespace cralgo {

struct sha2_32_secrets {
	~sha2_32_secrets() {
		secure_scrub_memory(this, sizeof(sha2_32_secrets));
	}

	uint32_t digest[8];
	uint8_t buffer[64];
	size_t length;
};

void sha256_clear(sha2_32_secrets *secrets);

void sha256_update(sha2_32_secrets *secrets, const uint8_t in[], size_t length);

void sha256_finalize(sha2_32_secrets *secrets, uint8_t out[32]);

} // namespace cralgo
