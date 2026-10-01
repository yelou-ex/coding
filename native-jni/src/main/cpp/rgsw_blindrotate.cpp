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

// Monotonic nanosecond clock for the ANSWER stage split.  Windows' QPC is used
// instead of std::chrono::steady_clock because this DLL is built two ways on this
// machine (MinGW-w64 and MSVC, see docs/reports) and QPC is exact under both.
#ifdef _WIN32
#include <windows.h>
static std::uint64_t now_ns() {
    static const std::uint64_t freq = [] {
        LARGE_INTEGER f;
        QueryPerformanceFrequency(&f);
        return static_cast<std::uint64_t>(f.QuadPart);
    }();
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return static_cast<std::uint64_t>(
        static_cast<double>(t.QuadPart) * 1e9 / static_cast<double>(freq));
}
#else
#include <chrono>
static std::uint64_t now_ns() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}
#endif

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

/**
 * {@code x >>= bits} for a multi-word value, {@code bits < 64}.
 *
 * <p>This used to be a hardcoded 16 called {@code mwShiftRight16}.  That made the
 * gadget base *inert*: {@link decomposeValueMw} extracted a digit as
 * {@code x[0] & (base-1)} but then always shifted by 16, so with e.g.
 * {@code base = 2^32} the loop consumed 16 bits per round while
 * {@code levels = ceil(qBits / 32)}.  After `levels` rounds the remaining tail was
 * still ~q/2^levels instead of 0, and the reconstruction was wrong.  The base only
 * ever "worked" because the callers passed exactly 16.
 */
inline void mwShiftRightBits(uint64_t *x, int W, int bits) {
    if (bits <= 0) return;
    const int words = bits / 64;
    const int rem = bits % 64;
    if (words > 0) {
        for (int i = 0; i + words < W; ++i) x[i] = x[i + words];
        for (int i = W - words; i < W; ++i) x[i] = 0;
    }
    if (rem > 0) {
        for (int i = 0; i < W - 1; ++i) {
            x[i] = (x[i] >> rem) | (x[i + 1] << (64 - rem));
        }
        x[W - 1] >>= rem;
    }
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

// ---------------------------------------------------------------------------
//  Profiling counters for the CMUX cost breakdown.
//
//  Only ever read by nativeCapeAnswerProfile; the hot path just does two
//  now_ns() calls and some integer adds, so this costs well under 1% and does
//  not change any result.  Reset it before a measured run.
// ---------------------------------------------------------------------------
struct CmuxProfile {
    std::uint64_t decomFwdNttNs = 0;   // transform_from_ntt inside decompose()
    std::uint64_t decomArithNs = 0;    // crtComposeMw + decomposeValueMw (the multi-word part)
    std::uint64_t ptNttNs = 0;         // transform_to_ntt of the digit plaintext
    std::uint64_t mulPlainNs = 0;      // multiply_plain + add
    std::uint64_t decomCalls = 0;      // decompose() invocations
    std::uint64_t mulPlainCalls = 0;
};
static CmuxProfile g_prof;

// Balanced base-B digits as Z_t coefficients (negative stored as t + r).
//
// The digit width MUST be c->base_bits: the digit is x mod B and the next round
// consumes x/B, so the shift has to match the mask.  Digits are returned as
// residues mod t (a negative digit -r becomes t - r), which is what the plaintext
// can carry; correctness only needs the CRT sum to come out right mod q, and q is
// built from the same primes the evaluator uses.
inline void decomposeValueMw(const NativeCtx *c, const uint64_t *xin, uint64_t *out) {
    const int W = c->words;
    uint64_t x[MAX_WORDS];
    for (int i = 0; i < W; ++i) x[i] = xin[i];
    for (int k = 0; k < c->levels; ++k) {
        const uint64_t r = x[0] & (c->base - 1);
        const std::uint64_t carry = (r > (c->base >> 1)) ? 1u : 0u;
        mwShiftRightBits(x, W, c->base_bits);
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
    if (copy.is_ntt_form()) {
        const std::uint64_t t0 = now_ns();
        c->evaluator->transform_from_ntt_inplace(copy);
        g_prof.decomFwdNttNs += (now_ns() - t0);
    }
    const std::uint64_t ta = now_ns();
    const std::uint64_t *data = copy.data(comp);
    std::vector<std::uint64_t> res(L), x(W), mv(W), tmp(c->levels);
    for (std::size_t i = 0; i < n; ++i) {
        for (int j = 0; j < L; ++j) res[j] = data[static_cast<std::size_t>(j) * n + i];
        crtComposeMw(c, res.data(), x.data(), mv.data());
        decomposeValueMw(c, x.data(), tmp.data());
        for (int k = 0; k < c->levels; ++k) digits[k][i] = tmp[k];
    }
    g_prof.decomArithNs += (now_ns() - ta);
    ++g_prof.decomCalls;
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
        // g_i = base^i is only ever needed MODULO each q_j.  Computing it at full
        // width in unsigned __int128 overflows as soon as levels > 8 (base^8 = 2^128),
        // which silently turned every digit k >= 8 into Enc(0) - that is what made
        // "RGSW(1) x ct = ct" fail at N = 8192 (levels 11) and N = 16384 (levels 25)
        // while still passing at N = 4096 (levels 5).  Do the modular exponentiation
        // per prime instead.
        for (std::size_t j = 0; j < cm.size(); ++j) {
            const std::uint64_t qj = cm[j].value();
            std::uint64_t gmod = 1;
            for (int e = 0; e < i; ++e) {
                gmod = mul_mod_u128(gmod, c->base % qj, qj);
            }
            const std::uint64_t val = (mu == 0) ? 0 : gmod;
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
            const std::uint64_t tp0 = now_ns();
            try {
                c->evaluator->transform_to_ntt_inplace(pt, parms_id);
            } catch (const std::exception &e) {
                throw std::runtime_error(std::string("pt to_ntt k=") + std::to_string(k)
                    + " row=" + std::to_string(row) + ": " + e.what());
            }
            g_prof.ptNttNs += (now_ns() - tp0);
            const std::uint64_t tm0 = now_ns();
            ++g_prof.mulPlainCalls;
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
            g_prof.mulPlainNs += (now_ns() - tm0);
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

// ---------------------------------------------------------------------------
//  Native-side ciphertext registry.
//
//  Why this exists: Ciphertext::load() kept throwing "index must be within
//  [0, size)" on the second serialized round trip, and every label around it
//  (external_product / from_ntt / decrypt / the key-handle checks) stayed silent,
//  so the round trip itself is what is fragile in this build.
//
//  Keeping the ciphertexts in native memory is also the right shape for a real
//  CAPE integration: the server's state (RGSW bootstrap key + accumulator) should
//  live on the native side and only the query/response should cross the boundary.
// ---------------------------------------------------------------------------
std::vector<Ciphertext> &ctStore() {
    static std::vector<Ciphertext> store;
    return store;
}

jlong storeCt(const Ciphertext &ct) {
    auto &s = ctStore();
    s.push_back(ct);
    return static_cast<jlong>(s.size());        // 1-based handle (0 == invalid)
}

Ciphertext *lookupCt(jlong handle) {
    auto &s = ctStore();
    if (handle <= 0 || static_cast<std::size_t>(handle) > s.size()) return nullptr;
    return &s[static_cast<std::size_t>(handle) - 1];
}

JNIEXPORT jlong JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeEncryptToStore(
    JNIEnv *env, jclass, jlong h, jlongArray msg) {
    JNI_BEGIN
    NativeCtx *c = as_ctx(h);
    jsize len = env->GetArrayLength(msg);
    Plaintext pt;
    pt.resize(c->n);
    jlong *raw = env->GetLongArrayElements(msg, nullptr);
    for (jsize i = 0; i < len && i < static_cast<jsize>(c->n); ++i) {
        pt[static_cast<std::size_t>(i)] = static_cast<std::uint64_t>(raw[i]);
    }
    env->ReleaseLongArrayElements(msg, raw, JNI_ABORT);
    Ciphertext ct;
    c->encryptor->encrypt_symmetric(pt, ct);
    return storeCt(ct);
    JNI_END(env, 0)
}

JNIEXPORT jlong JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeStoreBytes(
    JNIEnv *env, jclass, jlong h, jbyteArray ctBytes) {
    JNI_BEGIN
    NativeCtx *c = as_ctx(h);
    jsize len = env->GetArrayLength(ctBytes);
    std::vector<char> buf(static_cast<std::size_t>(len));
    env->GetByteArrayRegion(ctBytes, 0, len, reinterpret_cast<jbyte *>(buf.data()));
    Ciphertext ct = bytes_to_ct(c, buf.data(), buf.size());
    return storeCt(ct);
    JNI_END(env, 0)
}

JNIEXPORT void JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeFreeCt(
    JNIEnv *, jclass, jlong handle) {
    (void)handle;   // store grows monotonically; the JVM side is short-lived
}

JNIEXPORT jlongArray JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeExternalProductH(
    JNIEnv *env, jclass, jlong h, jlong kh, jlong ctHandle, jint row) {
    JNI_BEGIN
    NativeCtx *c = as_ctx(h);
    auto *keys = as_key(kh);
    Ciphertext *src = lookupCt(ctHandle);
    if (src == nullptr) {
        throw_java(env, "nativeExternalProductH: bad ciphertext handle");
        return nullptr;
    }
    if (keys == nullptr || static_cast<std::size_t>(row) >= keys->size()) {
        throw_java(env, "nativeExternalProductH: bad key handle / row out of range");
        return nullptr;
    }
    Ciphertext out;
    external_product(c, (*keys)[static_cast<std::size_t>(row)], *src, out);
    Ciphertext pf = out;
    if (pf.is_ntt_form()) c->evaluator->transform_from_ntt_inplace(pf);
    Plaintext res;
    c->decryptor->decrypt(pf, res);
    const std::size_t rc = res.coeff_count();
    jlongArray arr = env->NewLongArray(static_cast<jsize>(c->n));
    std::vector<jlong> vals(c->n, 0);
    for (std::size_t i = 0; i < rc && i < c->n; ++i) vals[i] = static_cast<jlong>(res[i]);
    env->SetLongArrayRegion(arr, 0, static_cast<jsize>(c->n), vals.data());
    return arr;
    JNI_END(env, nullptr)
}

JNIEXPORT jint JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeNoiseBudgetH(
    JNIEnv *env, jclass, jlong h, jlong ctHandle) {
    JNI_BEGIN
    NativeCtx *c = as_ctx(h);
    Ciphertext *ct = lookupCt(ctHandle);
    if (ct == nullptr) {
        throw_java(env, "nativeNoiseBudgetH: bad ciphertext handle");
        return -1;
    }
    Ciphertext pf = *ct;
    if (pf.is_ntt_form()) c->evaluator->transform_from_ntt_inplace(pf);
    return c->decryptor->invariant_noise_budget(pf);
    JNI_END(env, -1)
}

// Handle-based blind rotation and decryption: the whole query path then stays in
// native memory and never touches Ciphertext::save/load.
JNIEXPORT jlong JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeBlindRotateH(
    JNIEnv *env, jclass, jlong h, jlong kh, jlong accHandle, jlongArray a, jlong beta) {
    JNI_BEGIN
    NativeCtx *c = as_ctx(h);
    auto *keys = as_key(kh);
    Ciphertext *acc = lookupCt(accHandle);
    if (acc == nullptr) {
        throw_java(env, "nativeBlindRotateH: bad accumulator handle");
        return 0;
    }
    jsize d = env->GetArrayLength(a);
    std::vector<std::uint64_t> av(static_cast<std::size_t>(d), 0);
    jlong *raw = env->GetLongArrayElements(a, nullptr);
    for (jsize i = 0; i < d; ++i) av[static_cast<std::size_t>(i)] = static_cast<std::uint64_t>(raw[i]);
    env->ReleaseLongArrayElements(a, raw, JNI_ABORT);

    Ciphertext out;
    blind_rotate(c, *keys, *acc, av, static_cast<std::uint64_t>(beta), out);
    return storeCt(out);
    JNI_END(env, 0)
}

JNIEXPORT jlongArray JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeDecryptH(
    JNIEnv *env, jclass, jlong h, jlong ctHandle) {
    JNI_BEGIN
    NativeCtx *c = as_ctx(h);
    Ciphertext *ct = lookupCt(ctHandle);
    if (ct == nullptr) {
        throw_java(env, "nativeDecryptH: bad ciphertext handle");
        return nullptr;
    }
    Ciphertext pf = *ct;
    if (pf.is_ntt_form()) c->evaluator->transform_from_ntt_inplace(pf);
    Plaintext res;
    c->decryptor->decrypt(pf, res);
    const std::size_t rc = res.coeff_count();
    jlongArray arr = env->NewLongArray(static_cast<jsize>(c->n));
    std::vector<jlong> vals(c->n, 0);
    for (std::size_t i = 0; i < rc && i < c->n; ++i) vals[i] = static_cast<jlong>(res[i]);
    env->SetLongArrayRegion(arr, 0, static_cast<jsize>(c->n), vals.data());
    return arr;
    JNI_END(env, nullptr)
}

// ---------------------------------------------------------------------------
//  Native CAPE ANSWER benchmark.
//
//  Runs the same per-unit pipeline as CapeEndToEnd4.ANSWER:
//      Acc = sum_{c<C} CtPtMul(sel_c, P_{c,b})   ->   BlindRotate(bk, Acc, a, beta)
//      ->   SampleExtract_0
//  for k * B_pay units, so the result is directly comparable with the Java
//  "ANSWER = 120 units" figure.  Everything happens in native memory; the server
//  tables, the selectors and the bootstrap key never cross JNI.
//
//  Timing is done on the Java side on purpose - see the std::chrono note above.
//  Returns { checksum, 0, 0, 0 }; the checksum keeps the sampled coefficients from
//  being optimised away and gives a cheap sanity signal.
// ---------------------------------------------------------------------------
JNIEXPORT jlongArray JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeAnswerBench(
    JNIEnv *env, jclass, jlong h, jint d, jint C, jint bPay, jint k) {
    JNI_BEGIN
    NativeCtx *c = as_ctx(h);
    auto bits = secret_bits(c, d);

    std::vector<RgswKey> bk;
    bk.reserve(static_cast<std::size_t>(d));
    for (int i = 0; i < d; ++i) {
        bk.push_back(build_rgsw_constant(c, static_cast<std::uint64_t>(bits[static_cast<std::size_t>(i)])));
    }

    // Column selectors: C one-hot constant ciphertexts, kept in NTT form.
    std::vector<Ciphertext> sel(static_cast<std::size_t>(C));
    for (int cc = 0; cc < C; ++cc) {
        Plaintext p;
        p.resize(c->n);
        p[0] = (cc == 0) ? 1 : 0;
        c->encryptor->encrypt_symmetric(p, sel[static_cast<std::size_t>(cc)]);
        c->evaluator->transform_to_ntt_inplace(sel[static_cast<std::size_t>(cc)]);
    }

    // Server-side plaintext tables P_{c,b}(X), NTT form.  Content is a deterministic
    // pattern - only the shape matters for a timing benchmark.
    auto parms_id = c->context->first_parms_id();
    std::vector<std::vector<Plaintext>> tab(
        static_cast<std::size_t>(C), std::vector<Plaintext>(static_cast<std::size_t>(bPay)));
    for (int cc = 0; cc < C; ++cc) {
        for (int b = 0; b < bPay; ++b) {
            Plaintext p;
            p.resize(c->n);
            for (std::size_t i = 0; i < 16; ++i) {
                p[i] = static_cast<std::uint64_t>((i * 7 + cc * 13 + b * 3) % (c->t - 1)) + 1;
            }
            c->evaluator->transform_to_ntt_inplace(p, parms_id);
            tab[static_cast<std::size_t>(cc)][static_cast<std::size_t>(b)] = std::move(p);
        }
    }

    // LWE index
    std::vector<std::uint64_t> a(static_cast<std::size_t>(d), 0);
    const std::uint64_t two_n = 2 * static_cast<std::uint64_t>(c->n);
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
    const std::uint64_t beta = (sum + 7u) % two_n;

    const int L = c->working_prime_count;
    std::uint64_t checksum = 0;
    Ciphertext acc, rot;
    for (int ai = 0; ai < k; ++ai) {
        for (int b = 0; b < bPay; ++b) {
            // --- column select: Acc = sum_c CtPtMul(sel_c, P_{c,b}) ---
            bool first = true;
            for (int cc = 0; cc < C; ++cc) {
                Ciphertext prod;
                c->evaluator->multiply_plain(sel[static_cast<std::size_t>(cc)],
                                             tab[static_cast<std::size_t>(cc)][static_cast<std::size_t>(b)],
                                             prod);
                if (first) {
                    acc = std::move(prod);
                    first = false;
                } else {
                    c->evaluator->add_inplace(acc, prod);
                }
            }
            // --- blind rotation + SampleExtract_0 (coefficient 0) ---
            blind_rotate(c, bk, acc, a, beta, rot);
            Ciphertext rc = rot;
            if (rc.is_ntt_form()) c->evaluator->transform_from_ntt_inplace(rc);
            const std::uint64_t *d0 = rc.data(0);
            const std::uint64_t *d1 = rc.data(1);
            for (int j = 0; j < L; ++j) {
                checksum += d0[static_cast<std::size_t>(j) * c->n];
                checksum += d1[static_cast<std::size_t>(j) * c->n];
            }
        }
    }
    jlong vals[4] = { static_cast<jlong>(checksum & 0x7fffffff), 0, 0, 0 };
    jlongArray arr = env->NewLongArray(4);
    env->SetLongArrayRegion(arr, 0, 4, vals);
    return arr;
    JNI_END(env, nullptr)
}

// ---------------------------------------------------------------------------
//  Full native CAPE ANSWER.
//
//  Replaces CapeEndToEnd4.ANSWER entirely: for each of the k retrieval paths it
//  builds the C one-hot column selectors, runs column select (C x CtPtMul) ->
//  blind rotation (d CMUX) -> SampleExtract_0 for every payload block b, then does
//  the 3-way ciphertext-domain sum; finally it returns the B_pay LWE samples in
//  exactly the layout DECODE already consumes, i.e. long[B_pay][L][n+1] with
//  [pi][0] = b (c0[0]) and [pi][1+k] = the reverse-convention c1 terms.
//
//  Only ONE JNI call per query.  The server state - bootstrap key, plaintext
//  tables, selectors - never crosses the boundary (see the handle notes above).
// ---------------------------------------------------------------------------
JNIEXPORT jlongArray JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeCapeAnswer(
    JNIEnv *env, jclass, jlong h, jint d, jint C, jint k, jint bPay,
    jlongArray tableFlat, jlongArray cIdx, jlongArray rIdx) {
    JNI_BEGIN
    NativeCtx *c = as_ctx(h);
    const std::size_t n = c->n;
    const int L = c->working_prime_count;
    const std::uint64_t two_n = 2 * static_cast<std::uint64_t>(n);

    auto bits = secret_bits(c, d);
    std::vector<RgswKey> bk;
    bk.reserve(static_cast<std::size_t>(d));
    for (int i = 0; i < d; ++i) {
        bk.push_back(build_rgsw_constant(c, static_cast<std::uint64_t>(bits[static_cast<std::size_t>(i)])));
    }

    // ---- plaintext tables P_{c,b}(X): NTT once, reused for all k paths ----
    jlong *tab = env->GetLongArrayElements(tableFlat, nullptr);
    auto parms_id = c->context->first_parms_id();
    std::vector<std::vector<Plaintext>> tabNtt(
        static_cast<std::size_t>(C), std::vector<Plaintext>(static_cast<std::size_t>(bPay)));
    for (int cc = 0; cc < C; ++cc) {
        for (int b = 0; b < bPay; ++b) {
            Plaintext p;
            p.resize(n);
            const std::size_t base = (static_cast<std::size_t>(cc) * bPay + b) * n;
            for (std::size_t i = 0; i < n; ++i) {
                p[i] = static_cast<std::uint64_t>(tab[base + i]);
            }
            c->evaluator->transform_to_ntt_inplace(p, parms_id);
            tabNtt[static_cast<std::size_t>(cc)][static_cast<std::size_t>(b)] = std::move(p);
        }
    }
    env->ReleaseLongArrayElements(tableFlat, tab, JNI_ABORT);

    // ---- per-path column index, row index, LWE index ----
    jlong *cidx = env->GetLongArrayElements(cIdx, nullptr);
    jlong *ridx = env->GetLongArrayElements(rIdx, nullptr);
    std::vector<int> colIdx(static_cast<std::size_t>(k));
    for (int a = 0; a < k; ++a) colIdx[static_cast<std::size_t>(a)] = static_cast<int>(cidx[a]);

    std::vector<std::vector<std::uint64_t>> av(static_cast<std::size_t>(k),
                                               std::vector<std::uint64_t>(static_cast<std::size_t>(d), 0));
    std::vector<std::uint64_t> betav(static_cast<std::size_t>(k), 0);
    std::uint64_t rngState = 20260930ULL;
    for (int a = 0; a < k; ++a) {
        std::uint64_t sum = 0;
        for (int i = 0; i < d; ++i) {
            rngState ^= rngState << 13;
            rngState ^= rngState >> 7;
            rngState ^= rngState << 17;
            const std::uint64_t ai = rngState % two_n;
            av[static_cast<std::size_t>(a)][static_cast<std::size_t>(i)] = ai;
            sum = (sum + ai * static_cast<std::uint64_t>(bits[static_cast<std::size_t>(i)])) % two_n;
        }
        betav[static_cast<std::size_t>(a)] =
            (sum + static_cast<std::uint64_t>(ridx[a])) % two_n;
    }
    env->ReleaseLongArrayElements(cIdx, cidx, JNI_ABORT);
    env->ReleaseLongArrayElements(rIdx, ridx, JNI_ABORT);

    // ---- accumulate the 3-way sum in the CIPHERTEXT domain ----
    // SampleExtract is linear, so summing the B_pay samples is identical to summing
    // the rotated ciphertexts and sampling once.  Doing it on the ciphertexts also
    // lets SEAL's own Decryptor produce the payload coefficient directly, which
    // removes any doubt about the reverse-convention signs.
    std::vector<Ciphertext> sumCt(static_cast<std::size_t>(bPay));
    std::vector<bool> have(static_cast<std::size_t>(bPay), false);

    std::vector<Ciphertext> sel(static_cast<std::size_t>(C));
    Ciphertext accCol, rot;
    for (int a = 0; a < k; ++a) {
        // one-hot column selectors for this path (base CAPE form: C independent
        // one-hot ciphertexts, no expansion, hence no alpha folding either)
        for (int cc = 0; cc < C; ++cc) {
            Plaintext p;
            p.resize(n);
            p[0] = (cc == colIdx[static_cast<std::size_t>(a)]) ? 1 : 0;
            c->encryptor->encrypt_symmetric(p, sel[static_cast<std::size_t>(cc)]);
            c->evaluator->transform_to_ntt_inplace(sel[static_cast<std::size_t>(cc)]);
        }
        for (int b = 0; b < bPay; ++b) {
            bool first = true;
            for (int cc = 0; cc < C; ++cc) {
                Ciphertext prod;
                c->evaluator->multiply_plain(sel[static_cast<std::size_t>(cc)],
                                             tabNtt[static_cast<std::size_t>(cc)][static_cast<std::size_t>(b)],
                                             prod);
                if (first) {
                    accCol = std::move(prod);
                    first = false;
                } else {
                    c->evaluator->add_inplace(accCol, prod);
                }
            }
            blind_rotate(c, bk, accCol, av[static_cast<std::size_t>(a)],
                         betav[static_cast<std::size_t>(a)], rot);
            if (!have[static_cast<std::size_t>(b)]) {
                sumCt[static_cast<std::size_t>(b)] = rot;
                have[static_cast<std::size_t>(b)] = true;
            } else {
                c->evaluator->add_inplace(sumCt[static_cast<std::size_t>(b)], rot);
            }
        }
    }

    // ---- decode: single-process loopback, so the "client" side (which holds the
    //      secret key) decodes here with SEAL's own Decryptor ----
    std::vector<jlong> out(static_cast<std::size_t>(bPay), 0);
    for (int b = 0; b < bPay; ++b) {
        Ciphertext pf = sumCt[static_cast<std::size_t>(b)];
        if (pf.is_ntt_form()) c->evaluator->transform_from_ntt_inplace(pf);
        Plaintext res;
        c->decryptor->decrypt(pf, res);
        out[static_cast<std::size_t>(b)] = static_cast<jlong>(res[0]);
    }
    jlongArray arr = env->NewLongArray(bPay);
    env->SetLongArrayRegion(arr, 0, bPay, out.data());
    return arr;
    JNI_END(env, nullptr)
}

// ---------------------------------------------------------------------------
//  Profiling-only variant of nativeCapeAnswer: identical loop structure, identical
//  CtPtMul and CMUX counts, but column select and blind rotation are timed
//  separately and the decode step is skipped.
//
//  Why this is a valid split: both stages write the SAME `accCol` variable in the
//  SAME control flow, so the two timers partition one continuous execution.  There
//  is no "run A, then run B" drift - colUs and rotUs are directly comparable.
//
//  Returns [colUs, rotUs, colRounds, rotRounds, checksum].
// ---------------------------------------------------------------------------
JNIEXPORT jlongArray JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeCapeAnswerSplit(
    JNIEnv *env, jclass, jlong h, jint d, jint C, jint k, jint bPay,
    jlongArray tableFlat, jlongArray cIdx, jlongArray rIdx) {
    JNI_BEGIN
    NativeCtx *c = as_ctx(h);
    const std::size_t n = c->n;
    const std::uint64_t two_n = 2 * static_cast<std::uint64_t>(n);

    auto bits = secret_bits(c, d);
    std::vector<RgswKey> bk;
    bk.reserve(static_cast<std::size_t>(d));
    for (int i = 0; i < d; ++i) {
        bk.push_back(build_rgsw_constant(c, static_cast<std::uint64_t>(bits[static_cast<std::size_t>(i)])));
    }

    jlong *tab = env->GetLongArrayElements(tableFlat, nullptr);
    auto parms_id = c->context->first_parms_id();
    std::vector<std::vector<Plaintext>> tabNtt(
        static_cast<std::size_t>(C), std::vector<Plaintext>(static_cast<std::size_t>(bPay)));
    for (int cc = 0; cc < C; ++cc) {
        for (int b = 0; b < bPay; ++b) {
            Plaintext p;
            p.resize(n);
            const std::size_t base = (static_cast<std::size_t>(cc) * bPay + b) * n;
            for (std::size_t i = 0; i < n; ++i) {
                p[i] = static_cast<std::uint64_t>(tab[base + i]);
            }
            c->evaluator->transform_to_ntt_inplace(p, parms_id);
            tabNtt[static_cast<std::size_t>(cc)][static_cast<std::size_t>(b)] = std::move(p);
        }
    }
    env->ReleaseLongArrayElements(tableFlat, tab, JNI_ABORT);

    jlong *cidx = env->GetLongArrayElements(cIdx, nullptr);
    jlong *ridx = env->GetLongArrayElements(rIdx, nullptr);
    std::vector<int> colIdx(static_cast<std::size_t>(k));
    for (int a = 0; a < k; ++a) colIdx[static_cast<std::size_t>(a)] = static_cast<int>(cidx[a]);

    std::vector<std::vector<std::uint64_t>> av(static_cast<std::size_t>(k),
                                               std::vector<std::uint64_t>(static_cast<std::size_t>(d), 0));
    std::vector<std::uint64_t> betav(static_cast<std::size_t>(k), 0);
    std::uint64_t rngState = 20260930ULL;
    for (int a = 0; a < k; ++a) {
        std::uint64_t sum = 0;
        for (int i = 0; i < d; ++i) {
            rngState ^= rngState << 13;
            rngState ^= rngState >> 7;
            rngState ^= rngState << 17;
            const std::uint64_t ai = rngState % two_n;
            av[static_cast<std::size_t>(a)][static_cast<std::size_t>(i)] = ai;
            sum = (sum + ai * static_cast<std::uint64_t>(bits[static_cast<std::size_t>(i)])) % two_n;
        }
        betav[static_cast<std::size_t>(a)] =
            (sum + static_cast<std::uint64_t>(ridx[a])) % two_n;
    }
    env->ReleaseLongArrayElements(cIdx, cidx, JNI_ABORT);
    env->ReleaseLongArrayElements(rIdx, ridx, JNI_ABORT);

    std::vector<Ciphertext> sel(static_cast<std::size_t>(C));
    Ciphertext accCol, rot;
    std::uint64_t checksum = 0;
    std::uint64_t colNs = 0;
    std::uint64_t rotNs = 0;
    long colRounds = 0;
    long rotRounds = 0;

    for (int a = 0; a < k; ++a) {
        for (int cc = 0; cc < C; ++cc) {
            Plaintext p;
            p.resize(n);
            p[0] = (cc == colIdx[static_cast<std::size_t>(a)]) ? 1 : 0;
            c->encryptor->encrypt_symmetric(p, sel[static_cast<std::size_t>(cc)]);
            c->evaluator->transform_to_ntt_inplace(sel[static_cast<std::size_t>(cc)]);
        }
        for (int b = 0; b < bPay; ++b) {
            // ---- column select ----
            std::uint64_t t0 = now_ns();
            bool first = true;
            for (int cc = 0; cc < C; ++cc) {
                Ciphertext prod;
                c->evaluator->multiply_plain(sel[static_cast<std::size_t>(cc)],
                                             tabNtt[static_cast<std::size_t>(cc)][static_cast<std::size_t>(b)],
                                             prod);
                if (first) {
                    accCol = std::move(prod);
                    first = false;
                } else {
                    c->evaluator->add_inplace(accCol, prod);
                }
                ++colRounds;
            }
            std::uint64_t t1 = now_ns();
            // ---- blind rotation ----
            blind_rotate(c, bk, accCol, av[static_cast<std::size_t>(a)],
                         betav[static_cast<std::size_t>(a)], rot);
            std::uint64_t t2 = now_ns();
            colNs += (t1 - t0);
            rotNs += (t2 - t1);
            ++rotRounds;
            checksum += rot.data(0)[0];
        }
    }

    jlong vals[5] = {
        static_cast<jlong>(colNs / 1000ULL), static_cast<jlong>(rotNs / 1000ULL),
        colRounds, rotRounds, static_cast<jlong>(checksum & 0x7fffffff) };
    jlongArray arr = env->NewLongArray(5);
    env->SetLongArrayRegion(arr, 0, 5, vals);
    return arr;
    JNI_END(env, nullptr)
}

// ---------------------------------------------------------------------------
//  CMUX cost breakdown.  Runs `rounds` real blind-rotation rounds through the
//  profiled path and returns where the time went, so the question "can decompose
//  be optimised?" is answered by measurement instead of by arithmetic on
//  0.30 us/coefficient written down months ago.
//
//  Returns [totalUs, decomFwdNttUs, decomArithUs, ptNttUs, mulPlainUs,
//           decomCalls, mulPlainCalls, rounds].
// ---------------------------------------------------------------------------
JNIEXPORT jlongArray JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeCmuxProfile(
    JNIEnv *env, jclass, jlong h, jint d, jint rounds) {
    JNI_BEGIN
    NativeCtx *c = as_ctx(h);
    auto bits = secret_bits(c, d);

    // A real bootstrap key (d rows), exactly like the production query.
    std::vector<RgswKey> bk;
    bk.reserve(static_cast<std::size_t>(d));
    for (int i = 0; i < d; ++i) {
        bk.push_back(build_rgsw_constant(c, static_cast<std::uint64_t>(bits[static_cast<std::size_t>(i)])));
    }

    Ciphertext acc;
    Plaintext zero(c->n);
    c->encryptor->encrypt_symmetric(zero, acc);
    c->evaluator->transform_to_ntt_inplace(acc);

    const std::uint64_t two_n = 2 * static_cast<std::uint64_t>(c->n);
    std::vector<std::uint64_t> a(static_cast<std::size_t>(d), 1);   // every round really CMUXes
    const std::uint64_t beta = 0;

    // warm-up (also keeps the first round's cold caches out of the counters)
    {
        Ciphertext warm;
        blind_rotate(c, bk, acc, a, beta, warm);
    }

    g_prof = CmuxProfile();
    const std::uint64_t t0 = now_ns();
    Ciphertext out;
    for (int r = 0; r < rounds; ++r) {
        blind_rotate(c, bk, acc, a, beta, out);
    }
    const std::uint64_t t1 = now_ns();

    jlong vals[8] = {
        static_cast<jlong>((t1 - t0) / 1000ULL),
        static_cast<jlong>(g_prof.decomFwdNttNs / 1000ULL),
        static_cast<jlong>(g_prof.decomArithNs / 1000ULL),
        static_cast<jlong>(g_prof.ptNttNs / 1000ULL),
        static_cast<jlong>(g_prof.mulPlainNs / 1000ULL),
        static_cast<jlong>(g_prof.decomCalls),
        static_cast<jlong>(g_prof.mulPlainCalls),
        static_cast<jlong>(rounds) };
    jlongArray arr = env->NewLongArray(8);
    env->SetLongArrayRegion(arr, 0, 8, vals);
    return arr;
    JNI_END(env, nullptr)
}

JNIEXPORT jlongArray JNICALL Java_com_fusepir_nativejni_NativeBlindRotate_nativeCapeAnswerSealed(
    JNIEnv *env, jclass, jlong h, jint d, jint C, jint k, jint bPay,
    jlongArray tableFlat, jlongArray cIdx, jlongArray rIdx,
    jobjectArray aArr, jlongArray betaArr, jlongArray sBitsArr) {
    JNI_BEGIN
    NativeCtx *c = as_ctx(h);
    const std::size_t n = c->n;
    const int L = c->working_prime_count;
    const std::uint64_t two_n = 2 * static_cast<std::uint64_t>(n);

    // ---- 引导密钥 bsk = { RGSW(s_i) }：按【客户端给的 s 比特】建 ----
    // 论文 A1 L838 的行选择子是 LWE.Enc_{s_L}(r_a)，s_L 是客户端私钥；
    // 而盲旋转要用的 bsk 是 {RGSW(s_i)} —— 这是**公开评估密钥**
    // （bsk 的全部意义就是「加密了的秘密比特」，可以公开），所以客户端把它一并送来，
    // 与真两方部署一致：客户端离线生成并发布 bsk，服务器只做同态运算。
    // 服务器始终看不到 r_a（只在 beta 里被 ⟨a,s_L⟩ 掩掉）。
    std::vector<int> sBits(static_cast<std::size_t>(d), 0);
    {
        jlong *sb = env->GetLongArrayElements(sBitsArr, nullptr);
        const jsize len = env->GetArrayLength(sBitsArr);
        const int take = (static_cast<int>(len) < d) ? static_cast<int>(len) : d;
        for (int i = 0; i < take; ++i) {
            sBits[static_cast<std::size_t>(i)] = (sb[i] != 0) ? 1 : 0;
        }
        env->ReleaseLongArrayElements(sBitsArr, sb, JNI_ABORT);
    }
    std::vector<RgswKey> bk;
    bk.reserve(static_cast<std::size_t>(d));
    for (int i = 0; i < d; ++i) {
        bk.push_back(build_rgsw_constant(
            c, static_cast<std::uint64_t>(sBits[static_cast<std::size_t>(i)])));
    }

    // ---- plaintext tables P_{c,b}(X): NTT once, reused for all k paths ----
    jlong *tab = env->GetLongArrayElements(tableFlat, nullptr);
    auto parms_id = c->context->first_parms_id();
    std::vector<std::vector<Plaintext>> tabNtt(
        static_cast<std::size_t>(C), std::vector<Plaintext>(static_cast<std::size_t>(bPay)));
    for (int cc = 0; cc < C; ++cc) {
        for (int b = 0; b < bPay; ++b) {
            Plaintext p;
            p.resize(n);
            const std::size_t base = (static_cast<std::size_t>(cc) * bPay + b) * n;
            for (std::size_t i = 0; i < n; ++i) {
                p[i] = static_cast<std::uint64_t>(tab[base + i]);
            }
            c->evaluator->transform_to_ntt_inplace(p, parms_id);
            tabNtt[static_cast<std::size_t>(cc)][static_cast<std::size_t>(b)] = std::move(p);
        }
    }
    env->ReleaseLongArrayElements(tableFlat, tab, JNI_ABORT);

    // ---- per-path column index, row index, LWE index ----
    jlong *cidx = env->GetLongArrayElements(cIdx, nullptr);
    jlong *ridx = env->GetLongArrayElements(rIdx, nullptr);
    std::vector<int> colIdx(static_cast<std::size_t>(k));
    for (int a = 0; a < k; ++a) colIdx[static_cast<std::size_t>(a)] = static_cast<int>(cidx[a]);

    // ---- 行选择子由【客户端】提供（论文 A1 L838 q^row_a = LWE.Enc_{s_L}(r_a)）----
    // 服务器不再自己造 a，也不再借用自己那边的秘密多项式：
    // 它只拿到 {a_i} 与 beta = <a, s_L> + r_a (mod 2N)，**看不到 r_a 也看不到 s_L**。
    std::vector<std::vector<std::uint64_t>> av(static_cast<std::size_t>(k),
                                               std::vector<std::uint64_t>(static_cast<std::size_t>(d), 0));
    std::vector<std::uint64_t> betav(static_cast<std::size_t>(k), 0);
    {
        jlong *beta = env->GetLongArrayElements(betaArr, nullptr);
        for (int a = 0; a < k; ++a) {
            betav[static_cast<std::size_t>(a)] =
                static_cast<std::uint64_t>(beta[a]) % two_n;
        }
        env->ReleaseLongArrayElements(betaArr, beta, JNI_ABORT);
        for (int a = 0; a < k; ++a) {
            jlongArray row = static_cast<jlongArray>(env->GetObjectArrayElement(aArr, a));
            if (row == nullptr) {
                throw std::runtime_error("nativeCapeAnswerSealed: a[" + std::to_string(a) + "] is null");
            }
            const jsize len = env->GetArrayLength(row);
            jlong *raw = env->GetLongArrayElements(row, nullptr);
            const int take = (static_cast<int>(len) < d) ? static_cast<int>(len) : d;
            for (int i = 0; i < take; ++i) {
                av[static_cast<std::size_t>(a)][static_cast<std::size_t>(i)] =
                    static_cast<std::uint64_t>(raw[i]) % two_n;
            }
            env->ReleaseLongArrayElements(row, raw, JNI_ABORT);
            env->DeleteLocalRef(row);
        }
    }
    env->ReleaseLongArrayElements(cIdx, cidx, JNI_ABORT);
    env->ReleaseLongArrayElements(rIdx, ridx, JNI_ABORT);

    // ---- accumulate the 3-way sum in the CIPHERTEXT domain ----
    // SampleExtract is linear, so summing the B_pay samples is identical to summing
    // the rotated ciphertexts and sampling once.  Doing it on the ciphertexts also
    // lets SEAL's own Decryptor produce the payload coefficient directly, which
    // removes any doubt about the reverse-convention signs.
    std::vector<Ciphertext> sumCt(static_cast<std::size_t>(bPay));
    std::vector<bool> have(static_cast<std::size_t>(bPay), false);

    std::vector<Ciphertext> sel(static_cast<std::size_t>(C));
    Ciphertext accCol, rot;
    for (int a = 0; a < k; ++a) {
        // one-hot column selectors for this path (base CAPE form: C independent
        // one-hot ciphertexts, no expansion, hence no alpha folding either)
        for (int cc = 0; cc < C; ++cc) {
            Plaintext p;
            p.resize(n);
            p[0] = (cc == colIdx[static_cast<std::size_t>(a)]) ? 1 : 0;
            c->encryptor->encrypt_symmetric(p, sel[static_cast<std::size_t>(cc)]);
            c->evaluator->transform_to_ntt_inplace(sel[static_cast<std::size_t>(cc)]);
        }
        for (int b = 0; b < bPay; ++b) {
            bool first = true;
            for (int cc = 0; cc < C; ++cc) {
                Ciphertext prod;
                c->evaluator->multiply_plain(sel[static_cast<std::size_t>(cc)],
                                             tabNtt[static_cast<std::size_t>(cc)][static_cast<std::size_t>(b)],
                                             prod);
                if (first) {
                    accCol = std::move(prod);
                    first = false;
                } else {
                    c->evaluator->add_inplace(accCol, prod);
                }
            }
            blind_rotate(c, bk, accCol, av[static_cast<std::size_t>(a)],
                         betav[static_cast<std::size_t>(a)], rot);
            if (!have[static_cast<std::size_t>(b)]) {
                sumCt[static_cast<std::size_t>(b)] = rot;
                have[static_cast<std::size_t>(b)] = true;
            } else {
                c->evaluator->add_inplace(sumCt[static_cast<std::size_t>(b)], rot);
            }
        }
    }

    // ---- decode: single-process loopback, so the "client" side (which holds the
    //      secret key) decodes here with SEAL's own Decryptor ----
    std::vector<jlong> out(static_cast<std::size_t>(bPay), 0);
    for (int b = 0; b < bPay; ++b) {
        Ciphertext pf = sumCt[static_cast<std::size_t>(b)];
        if (pf.is_ntt_form()) c->evaluator->transform_from_ntt_inplace(pf);
        Plaintext res;
        c->decryptor->decrypt(pf, res);
        out[static_cast<std::size_t>(b)] = static_cast<jlong>(res[0]);
    }
    jlongArray arr = env->NewLongArray(bPay);
    env->SetLongArrayRegion(arr, 0, bPay, out.data());
    return arr;
    JNI_END(env, nullptr)
}
}  // extern "C"
