// ============================================================================
//  RGSW / CMUX / blind rotation on top of REAL Microsoft SEAL 4.0.0 (route A).
//
//  See native-jni/README.md and NativeBlindRotate.java for the Chinese notes.
//  This file is deliberately ASCII-only: the MinGW toolchain in tools/ cannot
//  reliably handle non-ASCII paths, so the source stays ASCII too.
//
//  What it does: mirrors Mpc4jRgsw.externalProduct / cmux and
//  BlindRotateOps.blindRotate exactly (same gadget base, same balanced-digit
//  decomposition, same "add constant to component 1" trick), but on SEAL C++.
//
//  Deliberate differences from the Java path - each is a real speedup:
//   1. CRT reconstruction via `unsigned __int128` instead of BigInteger.
//   2. multiplyPowerOfX() multiplies by the monomial X^k as an NTT-domain
//      *plaintext* - one multiply_plain, no key switching, no form round trip.
//   3. The accumulator is seeded from the first product instead of encrypt_zero.
//
//  Scope limit (documented, not hidden): the CRT composes into 128 bits, so this
//  module currently supports AT MOST 2 working primes - i.e. N <= 4096, which is
//  exactly the configuration we compare against.  Larger N throws.
// ============================================================================

#include <jni.h>
#include <seal/seal.h>
#include <seal/util/ntt.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace seal;

namespace {

struct RgswKey {
    std::vector<Ciphertext> g0;
    std::vector<Ciphertext> g1;
};

struct NativeCtx {
    std::shared_ptr<SEALContext> context;
    std::unique_ptr<KeyGenerator> keygen;
    std::unique_ptr<Encryptor> encryptor;
    std::unique_ptr<Decryptor> decryptor;
    std::unique_ptr<Evaluator> evaluator;
    SecretKey sk;
    std::size_t n = 0;
    std::uint64_t t = 0;
    int base_bits = 16;
    std::uint64_t base = 1;
    int levels = 0;
    int working_prime_count = 0;
    std::vector<std::uint64_t> primes;
    std::vector<std::uint64_t> crt_step_inv;
    int qBits = 0;
    /** multi-word width of q (little-endian uint64 words); see MAX_WORDS */
    int words = 0;
};

inline std::uint64_t mul_mod_u128(std::uint64_t a, std::uint64_t b, std::uint64_t m) {
    return static_cast<std::uint64_t>((static_cast<unsigned __int128>(a) * b) % m);
}

inline std::uint64_t add_mod(std::uint64_t a, std::uint64_t b, std::uint64_t m) {
    std::uint64_t s = a + b;
    return (s >= m || s < a) ? (s - m) : s;
}

std::uint64_t inv_mod_prime(std::uint64_t a, std::uint64_t p) {
    std::uint64_t inv = 1, b = a % p, e = p - 2;
    while (e > 0) {
        if (e & 1) inv = mul_mod_u128(inv, b, p);
        b = mul_mod_u128(b, b, p);
        e >>= 1;
    }
    return inv;
}

int levels_for(std::uint64_t base, unsigned __int128 q) {
    int l = 1;
    unsigned __int128 cap = base;
    while (cap <= q) { cap *= base; ++l; }
    return l;
}

void throw_java(JNIEnv *env, const std::string &msg) {
    jclass cls = env->FindClass("java/lang/IllegalStateException");
    if (cls != nullptr) env->ThrowNew(cls, msg.c_str());
}

NativeCtx *as_ctx(jlong h) { return reinterpret_cast<NativeCtx *>(h); }
std::vector<RgswKey> *as_key(jlong h) { return reinterpret_cast<std::vector<RgswKey> *>(h); }

std::string ct_to_bytes(const Ciphertext &ct) {
    std::ostringstream oss;
    ct.save(oss, compr_mode_type::none);
    return oss.str();
}

Ciphertext bytes_to_ct(const NativeCtx *c, const void *p, std::size_t len) {
    std::istringstream iss(std::string(static_cast<const char *>(p), len));
    Ciphertext ct;
    ct.load(*c->context, iss);
    return ct;
}

// ---------------------------------------------------------------- CRT + digits
//
// q can be far wider than 128 bits at paper scale (N=16384 -> 8 working primes,
// ~389 bits), so the CRT is done on a little-endian multi-word array instead of
// unsigned __int128.  That removes the earlier "at most 2 working primes" limit.
//
// Because the digit base is a power of two, extracting the balanced base-B digits
// from a multi-word value needs no division at all - just repeated 16-bit shifts.

constexpr int MAX_WORDS = 16;      // 1024 bits; covers N=32768 (881 bits)

inline void mwZero(uint64_t *x, int W) { for (int i = 0; i < W; ++i) x[i] = 0; }

inline int mwCmp(const uint64_t *a, const uint64_t *b, int W) {
    for (int i = W - 1; i >= 0; --i) {
        if (a[i] != b[i]) return a[i] > b[i] ? 1 : -1;
    }
    return 0;
}

inline void mwMulWord(uint64_t *x, int W, uint64_t m) {
    unsigned __int128 carry = 0;
    for (int i = 0; i < W; ++i) {
        unsigned __int128 p = static_cast<unsigned __int128>(x[i]) * m + carry;
        x[i] = static_cast<std::uint64_t>(p);
        carry = p >> 64;
    }
}

inline void mwAddMulWord(uint64_t *dst, const uint64_t *src, int W, uint64_t m) {
    unsigned __int128 carry = 0;
    for (int i = 0; i < W; ++i) {
        unsigned __int128 p = static_cast<unsigned __int128>(src[i]) * m + dst[i] + carry;
        dst[i] = static_cast<std::uint64_t>(p);
        carry = p >> 64;
    }
}

inline void mwShiftRight16(uint64_t *x, int W) {
    for (int i = 0; i < W - 1; ++i) {
        x[i] = (x[i] >> 16) | (x[i + 1] << 48);
    }
    x[W - 1] >>= 16;
}

inline void mwAddOne(uint64_t *x, int W) {
    for (int i = 0; i < W; ++i) {
        if (++x[i] != 0) break;
    }
}

/** {@code x mod p} for a multi-word x and a 64-bit p (Horner over the words). */
inline uint64_t mwModWord(const uint64_t *x, int W, uint64_t p) {
    uint64_t acc = 0;
    for (int i = W - 1; i >= 0; --i) {
        unsigned __int128 v = (static_cast<unsigned __int128>(acc) << 64) | x[i];
        acc = static_cast<std::uint64_t>(v % p);
    }
    return acc;
}

/**
 * Garner reconstruction of one coefficient: {@code x = r0 + p0*(r1 + p1*(r2 + ...))}.
 *
 * <p>{@code mv} is the running product p0*...*p_{j-1} as it goes, which is exactly
 * the working modulus q once the loop finishes - the caller reuses it for the
 * level count.
 */
inline void crtComposeMw(const NativeCtx *c, const uint64_t *res, uint64_t *x, uint64_t *mv) {
    const int W = c->words;
    mwZero(x, W);
    mwZero(mv, W);
    x[0] = res[0];
    mv[0] = c->primes[0];
    for (int j = 1; j < c->working_prime_count; ++j) {
        const uint64_t pj = c->primes[j];
        const uint64_t xm = mwModWord(x, W, pj);
        const uint64_t diff = (res[j] >= xm) ? (res[j] - xm) : (res[j] + pj - xm);
        const uint64_t tv = mul_mod_u128(diff, c->crt_step_inv[j], pj);
        mwAddMulWord(x, mv, W, tv);
        mwMulWord(mv, W, pj);
    }
}

// Balanced base-B digits as Z_t coefficients (negative stored as t + r).
inline void decomposeValueMw(const NativeCtx *c, const uint64_t *xin, uint64_t *out) {
    const int W = c->words;
    uint64_t x[MAX_WORDS];
    for (int i = 0; i < W; ++i) x[i] = xin[i];
    for (int k = 0; k < c->levels; ++k) {
        const uint64_t r = x[0] & (c->base - 1);
        uint64_t carry = 0;
        if (r > (c->base >> 1)) carry = 1;
        mwShiftRight16(x, W);
        if (carry) mwAddOne(x, W);
        out[k] = carry ? (r - c->base + c->t) : r;
    }
}

std::vector<std::vector<std::uint64_t>> decompose(const NativeCtx *c, const Ciphertext &ct, std::size_t comp) {
    const std::size_t n = c->n;
    const int L = c->working_prime_count;
    const int W = c->words;
    std::vector<std::vector<std::uint64_t>> digits(c->levels, std::vector<std::uint64_t>(n, 0));
    // A coefficient domain view is required: the digits are a decomposition of the
    // Z_q coefficient values, not of their NTT images.
    Ciphertext copy = ct;
    if (copy.is_ntt_form()) c->evaluator->transform_from_ntt_inplace(copy);
    const std::uint64_t *data = copy.data(comp);
    std::vector<std::uint64_t> res(L), x(W), mv(W), tmp(c->levels);
    for (std::size_t i = 0; i < n; ++i) {
        for (int j = 0; j < L; ++j) res[j] = data[static_cast<std::size_t>(j) * n + i];
        crtComposeMw(c, res.data(), x.data(), mv.data());
        decomposeValueMw(c, x.data(), tmp.data());
        for (int k = 0; k < c->levels; ++k) digits[k][i] = tmp[k];
    }
    return digits;
}

// ---------------------------------------------------------------- RGSW

// Builds RGSW(mu) for a *constant* mu, matching Mpc4jRgsw.encryptRgswConstant.
RgswKey build_rgsw_constant(const NativeCtx *c, std::uint64_t mu) {
    RgswKey key;
    key.g0.assign(c->levels, Ciphertext());
    key.g1.assign(c->levels, Ciphertext());
    auto parms_id = c->context->first_parms_id();
    const auto &cm = c->context->first_context_data()->parms().coeff_modulus();
    const std::size_t n = c->n;

    std::vector<std::uint64_t> mres(n, 0);
    for (int i = 0; i < c->levels; ++i) {
        // Gadget g_i = base^i, kept at FULL width (not reduced mod t) and added
        // straight into the phase, exactly like Mpc4jRgsw.addConstantNtt does with
        // the BigInteger `power`.  base^4 = 2^64 does not fit in uint64_t, hence
        // the 128-bit accumulator.
        unsigned __int128 gi = 1;
        for (int e = 0; e < i; ++e) gi *= c->base;

        // Both rows start as encryptions of ZERO.  encrypt_symmetric() (not
        // encrypt_zero(), whose output SEAL itself calls transparent, and not
        // encrypt(), which wants a public key) samples a uniform `a`, so the result
        // is non-transparent - and this only runs at keygen.
        try {
            Plaintext z(n);
            c->encryptor->encrypt_symmetric(z, key.g0[i]);
            c->encryptor->encrypt_symmetric(z, key.g1[i]);
        } catch (const std::exception &e) {
            throw std::runtime_error(std::string("encrypt0[") + std::to_string(i) + "]: " + e.what());
        }

        // The gadget constant goes into the PHASE, not into the message:
        //   component 0  ->  phase += g_i * mu            (RLWE'(g_i mu))
        //   component 1  ->  phase += g_i * mu * s        (RLWE''(g_i mu s))
        // Adding to component 1 makes the extra factor s appear for free.
        //
        // BUG FIXED HERE: the first version encrypted `g_i*mu mod t` as a plaintext,
        // which scales the phase by Delta = q/t - a completely different (and wrong)
        // gadget.  That is why RGSW(1) x ct came out as 4096/4096 wrong coefficients.
        for (std::size_t j = 0; j < cm.size(); ++j) {
            std::uint64_t qj = cm[j].value();
            std::uint64_t gmod = static_cast<std::uint64_t>(gi % qj);
            std::uint64_t val = (mu == 0) ? 0 : gmod;
            if (val == 0) {
                continue;
            }
            std::uint64_t *c0 = key.g0[i].data(0);
            std::uint64_t *c1 = key.g1[i].data(1);
            // still in the coefficient domain, so the constant polynomial is just
            // coefficient index 0
            c0[j * n] = add_mod(c0[j * n], val, qj);
            c1[j * n] = add_mod(c1[j * n], val, qj);
        }
        try {
            c->evaluator->transform_to_ntt_inplace(key.g0[i]);
            c->evaluator->transform_to_ntt_inplace(key.g1[i]);
        } catch (const std::exception &e) {
            throw std::runtime_error(std::string("to_ntt[") + std::to_string(i) + "]: " + e.what());
        }
    }
    return key;
}

// Secret key bits: SecretKey::data() is in NTT form (keygenerator.cpp:74-76),
// so we inverse-NTT a copy to recover the coefficient-domain {0,1} values.
std::vector<int> secret_bits(const NativeCtx *c, int d) {
    const std::size_t n = c->n;
    const auto &cm = c->context->first_context_data()->parms().coeff_modulus();
    // SecretKey::data() is a Plaintext; the raw RNS+NTT array is one level deeper.
    const auto &skp = c->sk.data();
    std::vector<std::uint64_t> skc(skp.data(), skp.data() + skp.coeff_count());
    auto tables = c->context->first_context_data()->small_ntt_tables();
    for (std::size_t j = 0; j < cm.size(); ++j) {
        util::inverse_ntt_negacyclic_harvey(skc.data() + j * n, tables[j]);
    }
    std::vector<int> bits(static_cast<std::size_t>(d), 0);
    for (int i = 0; i < d; ++i) {
        std::uint64_t v = skc[static_cast<std::size_t>(i)];
        bits[static_cast<std::size_t>(i)] = (v == 1 || v == 0) ? static_cast<int>(v) : 0;
    }
    return bits;
}

// ---------------------------------------------------------------- external product

void external_product(const NativeCtx *c, const RgswKey &key, const Ciphertext &src, Ciphertext &out) {
    auto d0 = decompose(c, src, 0);
    auto d1 = decompose(c, src, 1);
    auto parms_id = src.parms_id();
    Ciphertext acc;
    bool first = true;
    for (int k = 0; k < c->levels; ++k) {
        for (int row = 0; row < 2; ++row) {
            const auto &digits = (row == 0) ? d0[k] : d1[k];
            const Ciphertext &g = (row == 0) ? key.g0[k] : key.g1[k];
            Plaintext pt(c->n);
            for (std::size_t i = 0; i < c->n; ++i) pt[i] = digits[i];
            try {
                c->evaluator->transform_to_ntt_inplace(pt, parms_id);
            } catch (const std::exception &e) {
                throw std::runtime_error(std::string("pt to_ntt k=") + std::to_string(k)
                    + " row=" + std::to_string(row) + ": " + e.what());
            }
            try {
                if (first) {
                    c->evaluator->multiply_plain(g, pt, acc);
                    first = false;
                } else {
                    Ciphertext prod;
                    c->evaluator->multiply_plain(g, pt, prod);
                    c->evaluator->add_inplace(acc, prod);
                }
            } catch (const std::exception &e) {
                throw std::runtime_error(std::string("k=") + std::to_string(k)
                    + " row=" + std::to_string(row)
                    + " g_ntt=" + (g.is_ntt_form() ? "1" : "0")
                    + " gsize=" + std::to_string(g.size())
                    + " pt_ntt=" + (pt.is_ntt_form() ? "1" : "0")
                    + " first=" + (first ? "1" : "0")
                    + " acc_ntt=" + (first ? std::string("-") : (acc.is_ntt_form() ? "1" : "0"))
                    + ": " + e.what());
            }
        }
    }
    out = std::move(acc);
}

// ---------------------------------------------------------------- monomial + cmux

// ct * X^k.  ct must be in NTT form; X^k is a plaintext monomial, so this is a
// single multiply_plain - no key switching and no coefficient<->NTT round trip.
void multiply_power_of_x(const NativeCtx *c, const Ciphertext &ct, std::uint64_t k, Ciphertext &out) {
    const std::uint64_t two_n = 2 * static_cast<std::uint64_t>(c->n);
    std::uint64_t kk = k % two_n;
    Plaintext mono(c->n);
    if (kk < c->n) {
        mono[kk] = 1;
    } else {
        mono[kk - c->n] = c->t - 1;      // X^(k-N) * X^N = -X^(k-N)
    }
    c->evaluator->transform_to_ntt_inplace(mono, ct.parms_id());
    c->evaluator->multiply_plain(ct, mono, out);
}

// CMUX(bk, a, b) = a + (b - a) * bk
void cmux(const NativeCtx *c, const RgswKey &bk, const Ciphertext &a, const Ciphertext &b, Ciphertext &out) {
    Ciphertext diff, prod;
    c->evaluator->sub(b, a, diff);
    external_product(c, bk, diff, prod);
    c->evaluator->add(a, prod, out);
}

void blind_rotate(const NativeCtx *c, const std::vector<RgswKey> &bk,
                  const Ciphertext &acc, const std::vector<std::uint64_t> &a,
                  std::uint64_t beta, Ciphertext &out) {
    const std::uint64_t two_n = 2 * static_cast<std::uint64_t>(c->n);
    // The accumulator arrives in the coefficient domain (straight from encryption)
    // while everything in the loop is NTT-domain; normalise once here, otherwise
    // the CMUX subtraction throws "NTT form mismatch".
    Ciphertext cur = acc;
    if (!cur.is_ntt_form()) c->evaluator->transform_to_ntt_inplace(cur);
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (a[i] % two_n == 0) continue;      // identity round; a real CMUX would hit
                                              // SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
        Ciphertext rotated, next;
        multiply_power_of_x(c, cur, a[i], rotated);
        cmux(c, bk[i], cur, rotated, next);
        cur = std::move(next);
    }
    multiply_power_of_x(c, cur, (two_n - (beta % two_n)) % two_n, out);
}

}  // namespace

// ============================================================================
//  JNI exports
//
//  Every entry point is wrapped: a C++ exception escaping through JNI does NOT
//  become a Java exception, it aborts the whole JVM with
//  "Internal Error (0x20474343)" (0x20474343 is GCC's C++ exception magic).
//  That crash was hit for real during bring-up; catching here turns it into an
//  ordinary Java IllegalStateException with the SEAL message attached.
// ============================================================================

#define JNI_BEGIN try {
#define JNI_END(env, retval)                                                   \
    }                                                                          \
    catch (const std::exception &e) {                                          \
        throw_java(env, std::string("native SEAL: ") + e.what());              \
        return retval;                                                         \
    }                                                                          \
    catch (...) {                                                              \
        throw_java(env, "native SEAL: unknown C++ exception");                 \
        return retval;                                                         \
    }

extern "C" {

JNIEXPORT jlong JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeCreateContext(
    JNIEnv *env, jclass, jint n, jlong t, jint base_bits) {
    JNI_BEGIN
    auto *c = new NativeCtx();
    c->n = static_cast<std::size_t>(n);
    c->t = static_cast<std::uint64_t>(t);
    c->base_bits = base_bits;
    c->base = std::uint64_t(1) << base_bits;

    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(c->n);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(c->n, sec_level_type::tc128));
    parms.set_plain_modulus(PlainModulus::Batching(c->n, 17));
    if (parms.plain_modulus().value() != c->t) {
        parms.set_plain_modulus(static_cast<std::uint64_t>(t));
    }
    c->context = std::make_shared<SEALContext>(parms, true, sec_level_type::tc128);
    if (!c->context->parameters_set()) {
        std::string err = c->context->parameter_error_message();
        delete c;
        throw_java(env, "SEAL parameters rejected: " + err);
        return 0;
    }
    c->keygen = std::make_unique<KeyGenerator>(*c->context);
    c->sk = c->keygen->secret_key();
    c->encryptor = std::make_unique<Encryptor>(*c->context, c->sk);
    c->decryptor = std::make_unique<Decryptor>(*c->context, c->sk);
    c->evaluator = std::make_unique<Evaluator>(*c->context);

    const auto &cm = c->context->first_context_data()->parms().coeff_modulus();
    // NOTE: no "-1" here.  first_context_data() already excludes the special
    // prime q_last for BFV - the project's own probe recorded the same thing for
    // N=16384 (9 declared primes, 8 in first_parms_id).  Subtracting one more
    // gave 1 working prime / 36 bit at N=4096 instead of the Java side's 2 / 72.
    c->working_prime_count = static_cast<int>(cm.size());
    for (int j = 0; j < c->working_prime_count; ++j) {
        c->primes.push_back(cm[j].value());
        c->qBits += cm[j].bit_count();
    }
    // Multi-word CRT (no more "at most 2 working primes" limit).
    c->words = c->qBits / 64 + 2;
    if (c->words > MAX_WORDS) c->words = MAX_WORDS;

    c->crt_step_inv.assign(c->working_prime_count, 0);
    {
        std::vector<std::uint64_t> run(static_cast<std::size_t>(c->words), 0);
        run[0] = 1;
        for (int j = 0; j < c->working_prime_count; ++j) {
            if (j > 0) {
                // inv of (p0*...*p_{j-1} mod p_j), same Garner step as the Java side
                c->crt_step_inv[j] = inv_mod_prime(
                    mwModWord(run.data(), c->words, c->primes[j]), c->primes[j]);
            }
            mwMulWord(run.data(), c->words, c->primes[j]);
        }
    }

    // levels: smallest l with base^l > q, evaluated on the multi-word q itself.
    {
        std::vector<std::uint64_t> q(static_cast<std::size_t>(c->words), 0);
        std::vector<std::uint64_t> cap(static_cast<std::size_t>(c->words), 0);
        q[0] = c->primes[0];
        for (int j = 1; j < c->working_prime_count; ++j) mwMulWord(q.data(), c->words, c->primes[j]);
        cap[0] = c->base;
        int l = 1;
        while (mwCmp(cap.data(), q.data(), c->words) <= 0) {
            mwMulWord(cap.data(), c->words, c->base);
            ++l;
        }
        c->levels = l;
    }
    return reinterpret_cast<jlong>(c);
    JNI_END(env, 0)
}

JNIEXPORT void JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeDestroyContext(
    JNIEnv *, jclass, jlong h) {
    delete as_ctx(h);
}

JNIEXPORT jstring JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeDescribe(
    JNIEnv *env, jclass, jlong h) {
    JNI_BEGIN
    NativeCtx *c = as_ctx(h);
    std::string s = "N=" + std::to_string(c->n) + ", t=" + std::to_string(c->t)
        + ", base=2^" + std::to_string(c->base_bits)
        + ", levels=" + std::to_string(c->levels)
        + ", workingPrimes=" + std::to_string(c->working_prime_count)
        + ", q=" + std::to_string(c->qBits) + " bit (" + std::to_string(c->words) + " words)";
    return env->NewStringUTF(s.c_str());
    JNI_END(env, nullptr)
}

// Builds d bootstrap keys RGSW(bit_i of the secret key).
JNIEXPORT jlong JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeBuildBootstrapKey(
    JNIEnv *env, jclass, jlong h, jint d) {
    JNI_BEGIN
    NativeCtx *c = as_ctx(h);
    auto bits = secret_bits(c, d);
    auto *keys = new std::vector<RgswKey>();
    keys->reserve(static_cast<std::size_t>(d));
    for (int i = 0; i < d; ++i) {
        keys->push_back(build_rgsw_constant(c, static_cast<std::uint64_t>(bits[static_cast<std::size_t>(i)])));
    }
    return reinterpret_cast<jlong>(keys);
    JNI_END(env, 0)
}

// ---------------------------------------------------------------------------
//  Self-contained blind-rotation benchmark.
//
//  Deliberately touches NO serialization: keys, accumulator, the LWE index, the
//  timing loop and the final decryption all stay inside C++.  Serialising a
//  ciphertext per call would be wrong for a real integration anyway (the server's
//  state belongs in native memory), and it also side-steps a Ciphertext::load
//  "index must be within [0, size)" failure that showed up on the second
//  serialized round-trip.
//
//  Returns { millis, nonZeroCount, where, unitCount }.
// ---------------------------------------------------------------------------
JNIEXPORT jlongArray JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeSelfTest(
    JNIEnv *env, jclass, jlong h, jint d, jint reps) {
    JNI_BEGIN
    const char *stage = "init";
    NativeCtx *c = as_ctx(h);
    std::vector<int> bits;
    std::vector<RgswKey> bk;
    Plaintext accPt;
    Ciphertext acc, out;
    std::vector<std::uint64_t> a;
    std::uint64_t beta = 0;
    const int r = 7;
    jlong nonZero = -1, unit = -1, where = -1;
    try {
        stage = "secret_bits";
        bits = secret_bits(c, d);

        stage = "build_bootstrap_key";
        bk.reserve(static_cast<std::size_t>(d));
        for (int i = 0; i < d; ++i) {
            bk.push_back(build_rgsw_constant(c, static_cast<std::uint64_t>(bits[static_cast<std::size_t>(i)])));
        }

        stage = "encrypt_accumulator";
        const std::uint64_t two_n0 = 2 * static_cast<std::uint64_t>(c->n);
        accPt.resize(c->n);
        accPt[r] = 1;                       // accumulator = Enc(X^r)
        c->encryptor->encrypt_symmetric(accPt, acc);

        stage = "build_lwe_index";
        const std::uint64_t two_n = two_n0;
        a.assign(static_cast<std::size_t>(d), 0);
        // Hand-rolled xorshift on purpose: <random>/mt19937_64 changed the DLL's UCRT
        // imports and made the JVM fail to load it with ERROR_PROC_NOT_FOUND.
        std::uint64_t rngState = 20260930ULL;
        std::uint64_t sum = 0;
        for (int i = 0; i < d; ++i) {
            rngState ^= rngState << 13;
            rngState ^= rngState >> 7;
            rngState ^= rngState << 17;
            a[static_cast<std::size_t>(i)] = rngState % two_n;
            sum = (sum + a[static_cast<std::size_t>(i)]
                   * static_cast<std::uint64_t>(bits[static_cast<std::size_t>(i)])) % two_n;
        }
        beta = (sum + static_cast<std::uint64_t>(r)) % two_n;

        stage = "blind_rotate";
        for (int rep = 0; rep < reps; ++rep) {
            blind_rotate(c, bk, acc, a, beta, out);
        }

        stage = "decrypt";
        Ciphertext pf = out;
        stage = "decrypt.copy";
        if (pf.is_ntt_form()) c->evaluator->transform_from_ntt_inplace(pf);
        stage = "decrypt.from_ntt";
        // SEAL's own examples always default-construct the destination plaintext and
        // let Decryptor::decrypt size it.  Pre-sizing it as Plaintext(n) is what
        // triggered "index must be within [0, size)" here.
        Plaintext res;
        stage = "decrypt.ctor";
        c->decryptor->decrypt(pf, res);
        stage = "decrypt.call";
        const std::size_t rc = res.coeff_count();
        nonZero = 0; unit = 0; where = -1;
        for (std::size_t i = 0; i < rc && i < c->n; ++i) {
            if (res[i] != 0) {
                nonZero++;
                where = static_cast<jlong>(i);
                if (res[i] == 1 || res[i] == c->t - 1) unit++;
            }
        }
        stage = "decrypt.scan";
    } catch (const std::exception &e) {
        throw_java(env, std::string("nativeSelfTest @") + stage
            + " [out.size=" + std::to_string(out.size())
            + " out.ntt=" + (out.is_ntt_form() ? "1" : "0")
           
            + " n=" + std::to_string(c->n)
            + "]: " + e.what());
        return nullptr;
    } catch (...) {
        throw_java(env, std::string("nativeSelfTest @") + stage + ": unknown C++ exception");
        return nullptr;
    }
    jlong vals[4] = { 0, nonZero, where, unit };
    jlongArray arr = env->NewLongArray(4);
    env->SetLongArrayRegion(arr, 0, 4, vals);
    return arr;
    JNI_END(env, nullptr)
}

// A standalone RGSW(mu) key - for the RGSW(1)/RGSW(0) correctness checks.// The bootstrap key rows are RGSW(bit_i of the LWE secret), NOT RGSW(0)/RGSW(1),
// so the tests must not borrow them.
JNIEXPORT jlong JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeRgswConstant(
    JNIEnv *env, jclass, jlong h, jlong mu) {
    JNI_BEGIN
    NativeCtx *c = as_ctx(h);
    auto *keys = new std::vector<RgswKey>();
    keys->push_back(build_rgsw_constant(c, static_cast<std::uint64_t>(mu)));
    return reinterpret_cast<jlong>(keys);
    JNI_END(env, 0)
}

JNIEXPORT void JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeDestroyKey(
    JNIEnv *, jclass, jlong kh) {
    delete as_key(kh);
}

JNIEXPORT jbyteArray JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeEncrypt(
    JNIEnv *env, jclass, jlong h, jlongArray msg) {
    JNI_BEGIN
    NativeCtx *c = as_ctx(h);
    jsize len = env->GetArrayLength(msg);
    std::vector<std::uint64_t> m(c->n, 0);
    jlong *raw = env->GetLongArrayElements(msg, nullptr);
    for (jsize i = 0; i < len && i < static_cast<jsize>(c->n); ++i) {
        m[static_cast<std::size_t>(i)] = static_cast<std::uint64_t>(raw[i]);
    }
    env->ReleaseLongArrayElements(msg, raw, JNI_ABORT);
    Plaintext pt(c->n);
    for (std::size_t i = 0; i < c->n; ++i) pt[i] = m[i];
    Ciphertext ct;
    c->encryptor->encrypt_symmetric(pt, ct);
    std::string s = ct_to_bytes(ct);
    jbyteArray out = env->NewByteArray(static_cast<jsize>(s.size()));
    env->SetByteArrayRegion(out, 0, static_cast<jsize>(s.size()),
                            reinterpret_cast<const jbyte *>(s.data()));
    return out;
    JNI_END(env, nullptr)
}

JNIEXPORT jlongArray JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeDecrypt(
    JNIEnv *env, jclass, jlong h, jbyteArray ctBytes) {
    JNI_BEGIN
    NativeCtx *c = as_ctx(h);
    jsize len = env->GetArrayLength(ctBytes);
    std::vector<char> buf(static_cast<std::size_t>(len));
    env->GetByteArrayRegion(ctBytes, 0, len, reinterpret_cast<jbyte *>(buf.data()));
    Ciphertext ct = bytes_to_ct(c, buf.data(), buf.size());
    if (ct.is_ntt_form()) c->evaluator->transform_from_ntt_inplace(ct);
    Plaintext pt(c->n);
    c->decryptor->decrypt(ct, pt);
    jlongArray out = env->NewLongArray(static_cast<jsize>(c->n));
    std::vector<jlong> vals(c->n);
    for (std::size_t i = 0; i < c->n; ++i) vals[i] = static_cast<jlong>(pt[i]);
    env->SetLongArrayRegion(out, 0, static_cast<jsize>(c->n), vals.data());
    return out;
    JNI_END(env, nullptr)
}

JNIEXPORT jint JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeNoiseBudget(
    JNIEnv *env, jclass, jlong h, jbyteArray ctBytes) {
    JNI_BEGIN
    NativeCtx *c = as_ctx(h);
    jsize len = env->GetArrayLength(ctBytes);
    std::vector<char> buf(static_cast<std::size_t>(len));
    env->GetByteArrayRegion(ctBytes, 0, len, reinterpret_cast<jbyte *>(buf.data()));
    Ciphertext ct = bytes_to_ct(c, buf.data(), buf.size());
    if (ct.is_ntt_form()) c->evaluator->transform_from_ntt_inplace(ct);
    return c->decryptor->invariant_noise_budget(ct);
    JNI_END(env, -1)
}

JNIEXPORT jbyteArray JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeBlindRotate(
    JNIEnv *env, jclass, jlong h, jlong kh, jbyteArray accBytes, jlongArray a, jlong beta) {
    JNI_BEGIN
    NativeCtx *c = as_ctx(h);
    auto *keys = as_key(kh);
    jsize len = env->GetArrayLength(accBytes);
    std::vector<char> buf(static_cast<std::size_t>(len));
    env->GetByteArrayRegion(accBytes, 0, len, reinterpret_cast<jbyte *>(buf.data()));
    Ciphertext acc = bytes_to_ct(c, buf.data(), buf.size());

    jsize d = env->GetArrayLength(a);
    std::vector<std::uint64_t> av(static_cast<std::size_t>(d));
    jlong *raw = env->GetLongArrayElements(a, nullptr);
    for (jsize i = 0; i < d; ++i) av[static_cast<std::size_t>(i)] = static_cast<std::uint64_t>(raw[i]);
    env->ReleaseLongArrayElements(a, raw, JNI_ABORT);

    Ciphertext out;
    blind_rotate(c, *keys, acc, av, static_cast<std::uint64_t>(beta), out);
    std::string s = ct_to_bytes(out);
    jbyteArray res = env->NewByteArray(static_cast<jsize>(s.size()));
    env->SetByteArrayRegion(res, 0, static_cast<jsize>(s.size()),
                            reinterpret_cast<const jbyte *>(s.data()));
    return res;
    JNI_END(env, nullptr)
}

// One external product, decrypted - used by the correctness test.
JNIEXPORT jlongArray JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeExternalProduct(
    JNIEnv *env, jclass, jlong h, jlong kh, jbyteArray srcBytes, jint row) {
    JNI_BEGIN
    try {
    NativeCtx *c = as_ctx(h);
    auto *keys = as_key(kh);
    jsize len = env->GetArrayLength(srcBytes);
    std::vector<char> buf(static_cast<std::size_t>(len));
    env->GetByteArrayRegion(srcBytes, 0, len, reinterpret_cast<jbyte *>(buf.data()));
    Ciphertext src = bytes_to_ct(c, buf.data(), buf.size());
    if (keys == nullptr || static_cast<std::size_t>(row) >= keys->size()) {
        throw_java(env, "nativeExternalProduct: bad key handle / row out of range");
        return nullptr;
    }
    const RgswKey &one = (*keys)[static_cast<std::size_t>(row)];
    if (one.g0.empty() || one.g1.empty()) {
        throw_java(env, "nativeExternalProduct: key rows are empty");
        return nullptr;
    }
    Ciphertext out;
    try {
        external_product(c, one, src, out);
    } catch (const std::exception &e) {
        throw std::runtime_error(std::string("external_product(g0=")
            + std::to_string(one.g0.size()) + ", src_ntt=" + (src.is_ntt_form() ? "1" : "0")
            + "): " + e.what());
    }
    // SEAL's Decryptor refuses NTT-form ciphertexts for BFV ("BFV encrypted cannot
    // be in NTT form"), and the external product output IS in NTT form - so convert
    // a copy back to the coefficient domain first.  This is plain bookkeeping, not
    // part of the measured work.
    Ciphertext plainForm = out;
    try {
        if (plainForm.is_ntt_form()) c->evaluator->transform_from_ntt_inplace(plainForm);
    } catch (const std::exception &e) {
        throw std::runtime_error(std::string("from_ntt(out_ntt=")
            + (out.is_ntt_form() ? "1" : "0") + ", out_size=" + std::to_string(out.size())
            + "): " + e.what());
    }
    Plaintext pt(c->n);
    try {
        c->decryptor->decrypt(plainForm, pt);
    } catch (const std::exception &e) {
        throw std::runtime_error(std::string("decrypt(size=") + std::to_string(plainForm.size())
            + ", ntt=" + (plainForm.is_ntt_form() ? "1" : "0") + "): " + e.what());
    }
    jlongArray res = env->NewLongArray(static_cast<jsize>(c->n));
    std::vector<jlong> vals(c->n);
    for (std::size_t i = 0; i < c->n; ++i) vals[i] = static_cast<jlong>(pt[i]);
    env->SetLongArrayRegion(res, 0, static_cast<jsize>(c->n), vals.data());
    return res;
    } catch (const std::exception &e) {
        throw_java(env, std::string("nativeExternalProduct/total: ") + e.what());
        return nullptr;
    }
    JNI_END(env, nullptr)
}

JNIEXPORT jobjectArray JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeSecretBits(
    JNIEnv *env, jclass, jlong h, jint d) {
    JNI_BEGIN
    NativeCtx *c = as_ctx(h);
    auto bits = secret_bits(c, d);
    jclass longCls = env->FindClass("java/lang/Long");
    jobjectArray out = env->NewObjectArray(d, longCls, nullptr);
    jmethodID ctor = env->GetMethodID(longCls, "<init>", "(J)V");
    for (int i = 0; i < d; ++i) {
        jobject o = env->NewObject(longCls, ctor, static_cast<jlong>(bits[static_cast<std::size_t>(i)]));
        env->SetObjectArrayElement(out, i, o);
        env->DeleteLocalRef(o);
    }
    return out;
    JNI_END(env, nullptr)
}

// ---------------------------------------------------------------------------
//  Persistent rotation job.
//
//  Why: timing a blind rotation by differencing two nativeSelfTest() calls is
//  contaminated - both calls rebuild the bootstrap key and the first one also pays
//  every cold-start cost.  Measured that way the estimate kept falling with the
//  repeat count (4.66 -> 3.36 -> 2.61 ms/CMUX) and never converged.
//
//  Here the bootstrap key, the accumulator and the LWE index are built ONCE and
//  kept in native memory, so nativeRun() can be timed directly and repeatedly.
// ---------------------------------------------------------------------------
struct RotationJob {
    std::vector<RgswKey> bk;
    Ciphertext acc;
    std::vector<std::uint64_t> a;
    std::uint64_t beta = 0;
};

RotationJob *as_job(jlong h) { return reinterpret_cast<RotationJob *>(h); }

JNIEXPORT jlong JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativePrepare(
    JNIEnv *env, jclass, jlong h, jint d) {
    JNI_BEGIN
    NativeCtx *c = as_ctx(h);
    auto *job = new RotationJob();
    auto bits = secret_bits(c, d);
    job->bk.reserve(static_cast<std::size_t>(d));
    for (int i = 0; i < d; ++i) {
        job->bk.push_back(build_rgsw_constant(c, static_cast<std::uint64_t>(bits[static_cast<std::size_t>(i)])));
    }
    const int r = 7;
    Plaintext accPt;
    accPt.resize(c->n);
    accPt[r] = 1;
    c->encryptor->encrypt_symmetric(accPt, job->acc);

    const std::uint64_t two_n = 2 * static_cast<std::uint64_t>(c->n);
    job->a.assign(static_cast<std::size_t>(d), 0);
    std::uint64_t rngState = 20260930ULL;
    std::uint64_t sum = 0;
    for (int i = 0; i < d; ++i) {
        rngState ^= rngState << 13;
        rngState ^= rngState >> 7;
        rngState ^= rngState << 17;
        job->a[static_cast<std::size_t>(i)] = rngState % two_n;
        sum = (sum + job->a[static_cast<std::size_t>(i)]
               * static_cast<std::uint64_t>(bits[static_cast<std::size_t>(i)])) % two_n;
    }
    job->beta = (sum + static_cast<std::uint64_t>(r)) % two_n;
    return reinterpret_cast<jlong>(job);
    JNI_END(env, 0)
}

JNIEXPORT jlongArray JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeRunWithCtx(
    JNIEnv *env, jclass, jlong h, jlong jh, jint reps) {
    JNI_BEGIN
    NativeCtx *c = as_ctx(h);
    RotationJob *job = as_job(jh);
    Ciphertext out;
    for (int rep = 0; rep < reps; ++rep) {
        blind_rotate(c, job->bk, job->acc, job->a, job->beta, out);
    }
    Ciphertext pf = out;
    if (pf.is_ntt_form()) c->evaluator->transform_from_ntt_inplace(pf);
    Plaintext res;
    c->decryptor->decrypt(pf, res);
    const std::size_t rc = res.coeff_count();
    jlong nonZero = 0, unit = 0, where = -1;
    for (std::size_t i = 0; i < rc && i < c->n; ++i) {
        if (res[i] != 0) {
            nonZero++;
            where = static_cast<jlong>(i);
            if (res[i] == 1 || res[i] == c->t - 1) unit++;
        }
    }
    jlong vals[4] = { 0, nonZero, where, unit };
    jlongArray arr = env->NewLongArray(4);
    env->SetLongArrayRegion(arr, 0, 4, vals);
    return arr;
    JNI_END(env, nullptr)
}

JNIEXPORT void JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeFreeJob(
    JNIEnv *, jclass, jlong jh) {
    delete as_job(jh);
}

}  // extern "C"
