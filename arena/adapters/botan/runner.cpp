#include <botan/auto_rng.h>
#include <botan/pk_algs.h>
#include <botan/pubkey.h>
#include <botan/rng.h>
#include <botan/version.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

static constexpr int ITERATIONS = 20;
static constexpr int WARMUPS = 3;
using Clock = std::chrono::steady_clock;

static const char* env_or(const char* n, const char* fallback) {
   const char* v = std::getenv(n);
   return v && *v ? v : fallback;
}

static double ns_between(Clock::time_point a, Clock::time_point b) {
   return std::chrono::duration<double, std::nano>(b - a).count();
}

static void emit(const char* algorithm, const char* parameter, const char* op,
                 double latency_ns, size_t pk, size_t sk, size_t ct, size_t sig,
                 bool has_ct, bool has_sig) {
   const auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
   std::cout << "{\"schema_version\":1,\"run_id\":\"botan-" << algorithm << "-"
             << parameter << "-" << op << "\",\"implementation\":{\"id\":\"botan\",\"version\":\""
             << env_or("BOTAN_VERSION", Botan::version_string()) << "\",\"commit\":\""
             << env_or("BOTAN_COMMIT", "runtime") << "\"},\"algorithm\":{\"id\":\""
             << algorithm << "\",\"parameter_set\":\"" << parameter << "\"},\"operation\":\""
             << op << "\",\"environment\":{\"target\":\"" << env_or("ARENA_TARGET", "runtime")
             << "\",\"os\":\"" << env_or("ARENA_OS", "runtime") << "\",\"cpu\":\""
             << env_or("ARENA_CPU", "runtime") << "\",\"cpu_features\":[],\"compiler\":\""
             << env_or("ARENA_COMPILER", "c++") << "\",\"compiler_version\":\""
             << env_or("ARENA_COMPILER_VERSION", "runtime") << "\",\"optimization\":\""
             << env_or("ARENA_OPT", "release") << "\",\"harness_version\":\"arena-v1\"},\"measurement\":{\"iterations\":"
             << ITERATIONS << ",\"warmups\":" << WARMUPS << ",\"measurement_timestamp_unix_ns\":" << now << ",\"latency_ns\":"
             << latency_ns << ",\"throughput_ops_s\":" << (1e9 / latency_ns)
             << ",\"memory_bytes\":null,\"measurement_method\":\"steady_clock mean wall-clock latency\"},\"sizes\":{\"public_key_bytes\":"
             << pk << ",\"secret_key_bytes\":" << sk << ",\"ciphertext_bytes\":"
             << (has_ct ? std::to_string(ct) : "null") << ",\"signature_bytes\":"
             << (has_sig ? std::to_string(sig) : "null") << "}}\n";
}

static int kem(Botan::AutoSeeded_RNG& rng) {
   std::unique_ptr<Botan::Private_Key> sk;
   for(int i = 0; i < WARMUPS; ++i) sk = Botan::create_private_key("ML-KEM", rng, "ML-KEM-768");
   auto start = Clock::now();
   for(int i = 0; i < ITERATIONS; ++i) sk = Botan::create_private_key("ML-KEM", rng, "ML-KEM-768");
   auto end = Clock::now();
   emit("ml-kem", "768", "keygen", ns_between(start, end) / ITERATIONS, 1184, 2400, 1088, 0, true, false);

   auto pk = sk->public_key();
   Botan::PK_KEM_Encryptor enc(*pk, "Raw");
   Botan::PK_KEM_Decryptor dec(*sk, rng, "Raw");
   auto encapsulation = enc.encrypt(rng, 0);
   for(int i = 0; i < WARMUPS; ++i) (void)enc.encrypt(rng, 0);
   start = Clock::now();
   for(int i = 0; i < ITERATIONS; ++i) (void)enc.encrypt(rng, 0);
   end = Clock::now();
   emit("ml-kem", "768", "encaps", ns_between(start, end) / ITERATIONS, 1184, 2400,
        encapsulation.encapsulated_shared_key().size(), 0, true, false);

   for(int i = 0; i < WARMUPS; ++i) (void)dec.decrypt(encapsulation.encapsulated_shared_key(), 0);
   start = Clock::now();
   for(int i = 0; i < ITERATIONS; ++i) (void)dec.decrypt(encapsulation.encapsulated_shared_key(), 0);
   end = Clock::now();
   emit("ml-kem", "768", "decaps", ns_between(start, end) / ITERATIONS, 1184, 2400,
        encapsulation.encapsulated_shared_key().size(), 0, true, false);
   return 0;
}

static int dsa(Botan::AutoSeeded_RNG& rng) {
   std::unique_ptr<Botan::Private_Key> sk;
   for(int i = 0; i < WARMUPS; ++i) sk = Botan::create_private_key("ML-DSA", rng, "ML-DSA-6x5");
   auto start = Clock::now();
   for(int i = 0; i < ITERATIONS; ++i) sk = Botan::create_private_key("ML-DSA", rng, "ML-DSA-6x5");
   auto end = Clock::now();
   emit("ml-dsa", "65", "keygen", ns_between(start, end) / ITERATIONS, 1952, 4032, 0, 3309, false, true);

   auto pk = sk->public_key();
   Botan::PK_Signer signer(*sk, rng, "", Botan::Signature_Format::Standard);
   Botan::PK_Verifier verifier(*pk, "", Botan::Signature_Format::Standard);
   const std::vector<uint8_t> message(48, 0x42);
   std::vector<uint8_t> signature;
   for(int i = 0; i < WARMUPS; ++i) signature = signer.sign_message(message, rng);
   start = Clock::now();
   for(int i = 0; i < ITERATIONS; ++i) signature = signer.sign_message(message, rng);
   end = Clock::now();
   emit("ml-dsa", "65", "sign", ns_between(start, end) / ITERATIONS, 1952, 4032, 0,
        signature.size(), false, true);

   for(int i = 0; i < WARMUPS; ++i) {
      if(!verifier.verify_message(message, signature)) return 2;
   }
   start = Clock::now();
   for(int i = 0; i < ITERATIONS; ++i) {
      if(!verifier.verify_message(message, signature)) return 3;
   }
   end = Clock::now();
   emit("ml-dsa", "65", "verify", ns_between(start, end) / ITERATIONS, 1952, 4032, 0,
        signature.size(), false, true);
   return 0;
}

int main() {
   try {
      Botan::AutoSeeded_RNG rng;
      if(kem(rng) != 0 || dsa(rng) != 0) return 1;
      return 0;
   } catch(const std::exception& e) {
      std::cerr << "Botan Arena adapter error: " << e.what() << '\n';
      return 2;
   }
}
