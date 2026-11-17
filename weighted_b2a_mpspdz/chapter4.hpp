#pragma once
// Preserved Chapter 4 arithmetic and local authenticated sharing.
// Section 4.3 preprocessing uses SIF/EMP via svole/run_share.py.
// The prepare/share CLI exports accepted CRT shares for Chapter 5.

#include <sys/stat.h>
#include <array>
#include <cstdint>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <algorithm>        // max, min_element, find
#include <chrono>           // Monotonic execution timer.
#include <climits>          // INT_MAX
#include <filesystem>       // Create MP-SPDZ input directories.
#include <fstream>          // Write private inputs.
#include <iomanip>         // Format time with decimal places.
#include <sstream>         // Parse comma-separated Bash arguments.
#include <iostream>         // cout, cerr
#include <set>              // Detect duplicate party IDs.
#include <stdexcept>        // runtime_error
#include <utility>          // pair
#include <vector>           // Dynamic arrays.
#include <openssl/rand.h>   // Cryptographically secure random bytes.

using namespace std;

// ======================== Polynomial operations ========================
// vector<int> stores coefficients; no custom operator overloading is needed.
// Example: {1,0,1} represents 1+x^2; coefficients are low degree first.
struct Polynomial {
    vector<int> coeffs;

    // Construct Polynomial({1,0,1}) to represent 1+x^2.
    // The default constructor creates the zero polynomial.
    explicit Polynomial(vector<int> values = {0}) : coeffs(values) {
        if (coeffs.size() > INT_MAX) {
            throw runtime_error("Polynomial exceeds the supported degree range");
        }
        for (int value : coeffs) {
            if (value != 0 && value != 1) {
                throw runtime_error("F2 coefficients must be 0 or 1");
            }
        }
        normalize();
    }

    // Remove trailing high-degree zeros: {1,0,0} becomes {1}.
    // Always store the zero polynomial as {0}, never as an empty vector.
    void normalize() {
        if (coeffs.empty()) coeffs.push_back(0);
        while (coeffs.size() > 1 && coeffs.back() == 0) {
            coeffs.pop_back();
        }
    }

    // The zero polynomial has degree -1 in this implementation.
    // This convention also allows a zero secret in the degree check.
    int degree() const {
        if (coeffs.size() == 1 && coeffs[0] == 0) return -1;
        return static_cast<int>(coeffs.size()) - 1;
    }

    // const prevents changes; & passes a reference without copying.
    // Addition and subtraction in F2 are both XOR, written ^ in C++.
    Polynomial add(const Polynomial& other) const {
        vector<int> result(max(coeffs.size(), other.coeffs.size()), 0);
        for (size_t i = 0; i < coeffs.size(); ++i) result[i] ^= coeffs[i];
        for (size_t i = 0; i < other.coeffs.size(); ++i) result[i] ^= other.coeffs[i];
        return Polynomial(result);
    }

    // Polynomial multiplication; coefficient sums use XOR in F2.
    Polynomial mul(const Polynomial& other) const {
        size_t length = coeffs.size() + other.coeffs.size() - 1;
        if (length > INT_MAX) throw runtime_error("Polynomial product is too large");
        vector<int> result(length, 0);
        for (size_t i = 0; i < coeffs.size(); ++i) {
            if (coeffs[i] == 0) continue;
            for (size_t j = 0; j < other.coeffs.size(); ++j) {
                result[i + j] ^= other.coeffs[j];
            }
        }
        return Polynomial(result);
    }

    // Long division returns {quotient, remainder}.
    // The leading nonzero coefficient in F2 is 1, so no field inverse is needed.
    pair<Polynomial, Polynomial> div_rem(const Polynomial& divisor) const {
        if (divisor.degree() < 0) throw runtime_error("Cannot divide by the zero polynomial");
        Polynomial remainder = *this;  // Copy the current polynomial before modifying it.
        vector<int> quotient(coeffs.size(), 0);

        while (remainder.degree() >= divisor.degree()) {
            int shift = remainder.degree() - divisor.degree();
            quotient[shift] = 1;
            // Subtract x^shift * divisor; subtraction in F2 is XOR.
            for (size_t i = 0; i < divisor.coeffs.size(); ++i) {
                remainder.coeffs[i + shift] ^= divisor.coeffs[i];
            }
            remainder.normalize();
        }
        return {Polynomial(quotient), remainder};
    }

    Polynomial mod_poly(const Polynomial& modulus) const {
        return div_rem(modulus).second;
    }

    // Extended Euclid: find a such that a*this mod modulus = 1.
    // Track only the coefficient of this polynomial.
    Polynomial inverse_mod(const Polynomial& modulus) const {
        if (modulus.degree() <= 0) throw runtime_error("Modulus polynomial must have positive degree");
        Polynomial r0 = modulus;
        Polynomial r1 = mod_poly(modulus);
        Polynomial a0({0});
        Polynomial a1({1});

        while (r1.degree() >= 0) {
            auto division = r0.div_rem(r1); // auto infers the pair type.
            Polynomial a = a0.add(division.first.mul(a1));
            r0 = r1;
            r1 = division.second;
            a0 = a1;
            a1 = a;
        }
        if (r0.coeffs != vector<int>{1}) {
            throw runtime_error("Polynomials are not coprime; inverse does not exist");
        }
        return a0.mod_poly(modulus);
    }
};

// Shared helper routines.
vector<int> random_bits(int count) {
    if (count < 0) throw runtime_error("Random bit count cannot be negative");
    vector<unsigned char> bytes(count);
    if (count > 0 && RAND_bytes(bytes.data(), count) != 1) {
        throw runtime_error("OpenSSL random generation failed");
    }
    vector<int> bits(count);
    for (int i = 0; i < count; ++i) bits[i] = bytes[i] & 1;
    return bits;
}

void print_values(const vector<int>& values) {
    cout << "[";
    for (size_t i = 0; i < values.size(); ++i) {
        if (i > 0) cout << ",";
        cout << values[i];
    }
    cout << "]";
}

// ============================= Data structures =============================
struct Party {
    int id;                 // Original ID: 0,1,...,n_party-1.
    int weight;             // Scaled weight, also the degree of mi.
    Polynomial modulus;     // Public modulus polynomial mi.
};

struct Parameters {
    int field_modulus;      // Fixed to 2.
    int auth_field_bits = 128; // Fixed-width SIF extension-field elements.
    int scale;              // Common scaling factor c.
    int reconstruction_threshold; // Scaled reconstruction threshold T'=c*T.
    int privacy_threshold;        // Scaled privacy threshold t'=c*t.
    Polynomial m0;          // Irreducible secret modulus of degree d0=T'-t'.
    vector<Party> parties;
};

struct PartyShare {
    int party_id;           // Keep the ID with its share to prevent mismatched indices.
    Polynomial share;       // si=f mod mi.
};

struct BinaryAdditiveShare {
    int party_id;
    vector<int> coefficients; // Exactly d0 bits; index k is the share of the x^k coefficient.
};

// ========================== Algorithm 1: Setup ==========================
// Keep the original weights and thresholds as explicit input parameters.
// secret_bits is a minimum secret-space size; d0 may be larger.
Parameters generate_weighted_parameters(const vector<int>& weights,
                                       int T, int t, int secret_bits) {
    if (weights.empty()) throw runtime_error("Weights cannot be empty");
    if (t < 0 || T <= t) throw runtime_error("Require 0<=t<T");
    if (secret_bits <= 0) throw runtime_error("min_bits must be positive");
    long long total = 0;
    for (int w : weights) {
        if (w <= 0) throw runtime_error("Every weight must be positive");
        total += w;
    }
    if (total < T) throw runtime_error("Total weight is below T; no authorized set exists");

    // Integer ceiling divisions avoid floating-point arithmetic.
    // Ensure min(c*w_i)>=10 and d0=c*(T-t)>=secret_bits.
    int min_weight = *min_element(weights.begin(), weights.end());
    int c1 = 10 / min_weight + (10 % min_weight != 0);
    int c2 = secret_bits / (T - t) + (secret_bits % (T - t) != 0);
    int scale = max(c1, c2);
    if (1LL * scale * T >= INT_MAX) throw runtime_error("Scaled threshold is too large");

    Parameters params;
    params.field_modulus = 2;
    params.scale = scale;
    params.reconstruction_threshold = scale * T;
    params.privacy_threshold = scale * t;
    int d0 = params.reconstruction_threshold - params.privacy_threshold;
    Polynomial x({0, 1});
    // Section 4.3 requires m0 as well as party moduli to be irreducible.
    // Index 0 generates m0; subsequent indices generate original user IDs.
    for (size_t slot = 0; slot <= weights.size(); ++slot) {
        long long requested = slot == 0 ? d0 : 1LL * scale * weights[slot-1];
        if (requested >= INT_MAX) throw runtime_error("Scaled modulus degree is too large");
        int degree = static_cast<int>(requested);

        // Rabin test: collect degree/r for every distinct prime divisor r.
        vector<int> check_steps;
        int remaining = degree;
        for (int r = 2; r <= remaining / r; ++r) {
            if (remaining % r != 0) continue;
            check_steps.push_back(degree / r);
            while (remaining % r == 0) remaining /= r;
        }
        if (remaining > 1) check_steps.push_back(degree / remaining);

        Polynomial chosen;
        bool found = false;
        for (int attempt = 0; attempt < 10000; ++attempt) {
            vector<int> coeffs = random_bits(degree);
            coeffs[0] = 1;      // Constant term 1 excludes the factor x.
            coeffs.push_back(1); // A monic leading term fixes the requested degree.
            Polynomial candidate(coeffs);

            bool duplicate = slot != 0 && candidate.coeffs == params.m0.coeffs;
            for (const Party& party : params.parties) {
                if (party.modulus.coeffs == candidate.coeffs) duplicate = true;
            }
            if (duplicate) continue;

            Polynomial h = x.mod_poly(candidate);
            bool irreducible = true;
            for (int k = 1; k <= degree; ++k) {
                // Squaring in F2 has no cross terms: x^j becomes x^(2j).
                vector<int> square(2 * h.coeffs.size() - 1, 0);
                for (size_t j = 0; j < h.coeffs.size(); ++j) square[2 * j] = h.coeffs[j];
                h = Polynomial(square).mod_poly(candidate);

                if (find(check_steps.begin(), check_steps.end(), k) != check_steps.end()) {
                    // Require gcd(candidate, x^(2^k)-x)=1.
                    Polynomial a = candidate;
                    Polynomial b = h.add(x); // Subtraction equals addition in F2.
                    while (b.degree() >= 0) {
                        Polynomial remainder = a.mod_poly(b);
                        a = b;
                        b = remainder;
                    }
                    if (a.coeffs != vector<int>{1}) {
                        irreducible = false;
                        break;
                    }
                }
            }
            if (irreducible && h.coeffs == x.mod_poly(candidate).coeffs) {
                chosen = candidate;
                found = true;
                break;
            }
        }
        if (!found) throw runtime_error("Irreducible search exhausted; increase the common scale");
        if (slot == 0) params.m0 = chosen;
        else params.parties.push_back({static_cast<int>(slot-1), degree, chosen});
    }
    return params;
}

// Section 4.3 authentication uses 128-bit extension-field elements.
// Only addition and multiplication by a binary coefficient are needed here.
using AuthElement = array<unsigned char, 16>;
using AuthVector = vector<AuthElement>;
struct AuthMaterial {
    string sid;
    vector<int> u;
    vector<AuthVector> mac, key;
    vector<AuthElement> delta;
};

// Both dealer tags and verifier keys use reduction by a binary monic modulus.
AuthVector auth_mod(AuthVector value, const Polynomial& modulus) {
    int d = modulus.degree();
    for (int k = static_cast<int>(value.size())-1; k >= d; --k) {
        AuthElement lead = value[k];
        for (int j = 0; j <= d; ++j) if (modulus.coeffs[j])
            for (size_t byte = 0; byte < 16; ++byte) value[k-d+j][byte] ^= lead[byte];
    }
    value.resize(d); // Pad with zero elements when deg(modulus) is large.
    return value;
}

// Canonical, domain-separated encoding of H(sid, i, e, si, tau_i).
array<unsigned char, 32> auth_digest(const string& sid, int id, const vector<int>& e,
                                    const Polynomial& share, const AuthVector& tag) {
    vector<unsigned char> bytes;
    const string domain = "weighted-crt-auth-v1";
    bytes.insert(bytes.end(), domain.begin(), domain.end());
    auto integer = [&](uint64_t value) {
        for (int j = 0; j < 8; ++j) bytes.push_back(static_cast<unsigned char>(value >> (8*j)));
    };
    integer(sid.size()); bytes.insert(bytes.end(), sid.begin(), sid.end());
    integer(id); integer(e.size()); integer(tag.size());
    for (int bit : e) bytes.push_back(static_cast<unsigned char>(bit));
    for (size_t k = 0; k < tag.size(); ++k)
        bytes.push_back(k < share.coeffs.size() ? share.coeffs[k] : 0);
    for (const auto& element : tag) bytes.insert(bytes.end(), element.begin(), element.end());
    array<unsigned char, 32> digest{};
    if (!SHA256(bytes.data(), bytes.size(), digest.data())) throw runtime_error("SHA-256 failed");
    return digest;
}

// Local demo only: this process simulates the dealer and all online verifiers.
// Real preprocessing itself runs in separate SIF/EMP protocol processes.
// Files are consumed before parsing; failed attempts must use a fresh session.
AuthMaterial load_auth_material(const filesystem::path& directory, const string& sid, int T, int n) {
    vector<filesystem::path> files{directory / "dealer.bin"};
    for (int i = 0; i < n; ++i) files.push_back(directory / ("party-P"+to_string(i)+".bin"));
    for (const auto& path : files)
        if (!filesystem::exists(path) || filesystem::exists(path.string()+".used"))
            throw runtime_error("Missing or consumed authentication material; start a fresh session");
    for (auto& path : files) {
        filesystem::rename(path, path.string()+".used");
        path += ".used";
    }
    AuthMaterial auth;
    auth.sid = sid; auth.u.resize(T); auth.mac.resize(n); auth.key.resize(n); auth.delta.resize(n);
    for (int role = 0; role <= n; ++role) {
        ifstream input(files[role], ios::binary);
        string header, magic, received_sid;
        int received_T = 0, received_n = 0;
        getline(input, header);
        istringstream parsed(header);
        parsed >> magic >> received_sid >> received_T >> received_n;
        if (!parsed || magic != "AUTHV1" || received_sid != sid || received_T != T || received_n != n)
            throw runtime_error("Authentication session header mismatch");
        if (role == 0) {
            for (int j = 0; j < T; ++j) {
                int bit = input.get();
                if (bit != 0 && bit != 1) throw runtime_error("Invalid authenticated mask bit");
                auth.u[j] = bit;
            }
            for (int i = 0; i < n; ++i) {
                auth.mac[i].resize(T);
                input.read(reinterpret_cast<char*>(auth.mac[i].data()), 16LL*T);
            }
        } else {
            int i = role-1;
            input.read(reinterpret_cast<char*>(auth.delta[i].data()), 16);
            auth.key[i].resize(T);
            input.read(reinterpret_cast<char*>(auth.key[i].data()), 16LL*T);
        }
        if (!input || input.peek() != char_traits<char>::eof())
            throw runtime_error("Invalid authentication material length");
    }
    return auth;
}

// Authenticated Share: generate f once and use it for both CRT and MAC adjustment.
vector<Polynomial> verifiable_share(const Polynomial& secret, const Parameters& params,
                                    const AuthMaterial& auth, bool tamper) {
    int T = params.reconstruction_threshold, d0 = params.m0.degree();
    if (secret.degree() >= d0) throw runtime_error("Secret must satisfy deg(s0)<d0");
    Polynomial alpha(random_bits(T-d0));
    Polynomial f = secret.add(alpha.mul(params.m0));
    vector<int> e(T);
    for (int j = 0; j < T; ++j) e[j] = auth.u[j] ^ (j <= f.degree() ? f.coeffs[j] : 0);
    vector<Polynomial> shares;
    vector<array<unsigned char, 32>> digests;
    // Dealer: e is public, while each (si, hi) is a private packet to its owner.
    for (const Party& party : params.parties) {
        Polynomial si = f.mod_poly(party.modulus);
        AuthVector tag = auth_mod(auth.mac[party.id], party.modulus);
        digests.push_back(auth_digest(auth.sid, party.id, e, si, tag));
        shares.push_back(si);
    }
    if (tamper) { // Explicit negative-check mode; never used by normal batches.
        shares[0].coeffs[0] ^= 1;
        shares[0].normalize();
    }
    // Each simulated verifier uses only its own key and delta in this loop.
    for (const Party& party : params.parties) {
        int i = party.id;
        if (shares[i].degree() >= party.weight) throw runtime_error("Invalid authenticated share degree");
        AuthVector adjusted = auth.key[i];
        for (int j = 0; j < T; ++j) if (e[j])
            for (size_t byte = 0; byte < 16; ++byte) adjusted[j][byte] ^= auth.delta[i][byte];
        AuthVector expected = auth_mod(adjusted, party.modulus);
        for (size_t j = 0; j < shares[i].coeffs.size(); ++j) if (shares[i].coeffs[j])
            for (size_t byte = 0; byte < 16; ++byte) expected[j][byte] ^= auth.delta[i][byte];
        auto digest = auth_digest(auth.sid, i, e, shares[i], expected);
        if (CRYPTO_memcmp(digest.data(), digests[i].data(), digest.size()) != 0)
            throw runtime_error("Authenticated share verification failed; aborting session");
    }
    return shares;
}

// Both reconstruction and conversion reuse these CRT contributions.
// The selected IDs may appear in any order and need not be consecutive.
vector<Polynomial> crt_contributions(const vector<PartyShare>& selected_shares,
                                     const Parameters& params) {
    if (selected_shares.empty()) throw runtime_error("Selected set cannot be empty");
    set<int> ids;
    long long total_weight = 0;
    Polynomial product({1});
    for (const PartyShare& input : selected_shares) {
        int id = input.party_id;
        if (id < 0 || static_cast<size_t>(id) >= params.parties.size()) {
            throw runtime_error("Unknown party ID");
        }
        if (!ids.insert(id).second) throw runtime_error("Duplicate selected party ID");
        const Party& party = params.parties[id];
        if (input.share.degree() >= party.weight) throw runtime_error("Invalid share degree");
        total_weight += party.weight;
        product = product.mul(party.modulus); // M_A is the product of the selected moduli.
    }
    if (total_weight < params.reconstruction_threshold) {
        throw runtime_error("Selected weight is insufficient for reconstruction or conversion");
    }

    vector<Polynomial> contributions;
    for (const PartyShare& input : selected_shares) {
        const Polynomial& mi = params.parties[input.party_id].modulus;
        auto division = product.div_rem(mi);
        if (division.second.degree() >= 0) throw runtime_error("M_A must be divisible by mi");
        Polynomial m_a_i = division.first;
        Polynomial n_a_i = m_a_i.inverse_mod(mi);
        Polynomial lambda_i = n_a_i.mul(m_a_i);
        Polynomial sigma_i = lambda_i.mul(input.share).mod_poly(product);
        contributions.push_back(sigma_i);
    }
    return contributions;
}

// ====================== Algorithm 3: Reconstruction ======================
Polynomial crt_secret_reconstruct(const vector<PartyShare>& selected_shares,
                                  const Parameters& params) {
    vector<Polynomial> contributions = crt_contributions(selected_shares, params);
    Polynomial f;
    for (const Polynomial& sigma_i : contributions) f = f.add(sigma_i);
    // Each sigma_i has degree below deg(M_A); their XOR is exactly f.
    if (f.degree() >= params.reconstruction_threshold) {
        throw runtime_error("Reconstructed f has invalid degree; this check does not replace VSS");
    }
    return f.mod_poly(params.m0);
}

// Parse a CSV integer list such as 1,2,2; reused for all three lists.
vector<int> parse_list(const string& text) {
    if (text.empty() || text.back() == ',') throw runtime_error("CSV list cannot be empty or end in a comma");
    vector<int> values;
    string item;
    stringstream stream(text);
    while (getline(stream, item, ',')) {
        size_t consumed = 0;
        int value = stoi(item, &consumed);
        if (consumed != item.size()) throw runtime_error("CSV list contains a non-integer");
        values.push_back(value);
    }
    return values;
}

// Serialize validated integers rather than interpolating raw CLI strings.
string json_array(const vector<int>& values) {
    ostringstream output;
    output << "[";
    for (size_t i = 0; i < values.size(); ++i) {
        if (i > 0) output << ",";
        output << values[i];
    }
    output << "]";
    return output.str();
}

// Time authenticated Share plus all local verifications, excluding Setup, sVOLE, and file I/O.
vector<Polynomial> test_share(const Polynomial& secret, const Parameters& params,
                              const AuthMaterial& auth, bool tamper, double& share_seconds) {
    auto start = chrono::steady_clock::now();
    vector<Polynomial> shares = verifiable_share(secret, params, auth, tamper);
    auto end = chrono::steady_clock::now();
    share_seconds = chrono::duration<double>(end - start).count();
    return shares;
}

// Validate Chapter 4 reconstruction and return the selected shares.
// Keep validation outside both reported algorithm times.
vector<PartyShare> test_reconstruct(const vector<Polynomial>& shares,
                                  const vector<int>& selected_ids,
                                  const Polynomial& secret,
                                  const Parameters& params) {
    vector<PartyShare> selected;
    for (int id : selected_ids) {
        if (id < 0 || static_cast<size_t>(id) >= shares.size()) {
            throw runtime_error("Selected party ID does not exist");
        }
        selected.push_back({id, shares[id]});
    }
    Polynomial recovered = crt_secret_reconstruct(selected, params);
    if (recovered.coeffs != secret.coeffs) throw runtime_error("Chapter 4 reconstruction validation failed");
    // Optional local debugging; leave disabled for normal experiments.
    // cout << "Recovered secret="; print_values(recovered.coeffs); cout << "\n";
    return selected;
}

// ================================ main ================================
// The entry point calls test_share; reconstruction is an explicit opt-in test.
// Share timing is printed directly to the terminal.
int chapter4_entry(int argc, char* argv[]) {
    umask(0077);
    try {
        // Bash arguments: directory T t min_bits weights_csv ids_csv secret_csv.
        if (argc != 9) {
            throw runtime_error("Usage: ./weighted_crt directory T t min_bits weights_csv ids_csv secret_csv prepare|share|tamper-test");
        }
        filesystem::path directory(argv[1]);
        int T = stoi(argv[2]);
        int t = stoi(argv[3]);
        int min_bits = stoi(argv[4]);
        vector<int> weights = parse_list(argv[5]);
        vector<int> selected_ids = parse_list(argv[6]);
        Polynomial secret(parse_list(argv[7]));
        // Infer the total party count from the weight list.
        int n_party = static_cast<int>(weights.size());
        if (n_party < 2 || selected_ids.size() < 2) {
            throw runtime_error("This MP-SPDZ demo requires at least two total and selected parties");
        }

        string mode = argv[8];
        if (mode != "prepare" && mode != "share" && mode != "tamper-test")
            throw runtime_error("Expected prepare, share, or tamper-test mode");
        filesystem::create_directories(directory);
        Parameters params;
        string sid;
        if (mode == "prepare") {
            if (filesystem::exists(directory / "parameters.txt"))
                throw runtime_error("Use a fresh session directory; parameters already exist");
            params = generate_weighted_parameters(weights, T, t, min_bits);
            unsigned char session_bytes[32];
            if (RAND_bytes(session_bytes, sizeof(session_bytes)) != 1)
                throw runtime_error("Cannot generate session identifier");
            const char* hex = "0123456789abcdef";
            for (unsigned char byte : session_bytes) {
                sid += hex[byte >> 4]; sid += hex[byte & 15];
            }
            ofstream config(directory / "parameters.txt");
            config << sid << " " << params.scale << " " << params.reconstruction_threshold
                   << " " << params.privacy_threshold << " " << n_party << "\n";
            config << json_array(params.m0.coeffs) << "\n";
            for (const Party& party : params.parties) config << json_array(party.modulus.coeffs) << "\n";
            config.close();
            ofstream dims(directory / "auth_dimensions.txt");
            dims << n_party << " " << params.reconstruction_threshold << " " << sid << "\n";
            dims.close();
            if (!config || !dims) throw runtime_error("Cannot write public setup parameters");
            return 0;
        }
        // Reuse exactly the moduli generated before real sVOLE preprocessing.
        ifstream config(directory / "parameters.txt");
        int configured_n = 0;
        config >> sid >> params.scale >> params.reconstruction_threshold
               >> params.privacy_threshold >> configured_n;
        if (!config || configured_n != n_party || params.scale <= 0 ||
            1LL*params.scale*T != params.reconstruction_threshold ||
            1LL*params.scale*t != params.privacy_threshold)
            throw runtime_error("Setup parameters do not match this experiment");
        params.field_modulus = 2;
        string encoded;
        for (int slot = 0; slot <= n_party; ++slot) {
            config >> encoded;
            if (!config || encoded.size() < 3 || encoded.front() != '[' || encoded.back() != ']')
                throw runtime_error("Invalid public modulus encoding");
            Polynomial modulus(parse_list(encoded.substr(1, encoded.size()-2)));
            int expected = slot == 0 ? params.reconstruction_threshold-params.privacy_threshold
                                    : params.scale*weights[slot-1];
            if (modulus.degree() != expected) throw runtime_error("Public modulus degree mismatch");
            if (slot == 0) params.m0 = modulus;
            else params.parties.push_back({slot-1, expected, modulus});
        }
        AuthMaterial auth = load_auth_material(directory / "auth", sid,
                                               params.reconstruction_threshold, n_party);
        double share_seconds = 0;
        vector<Polynomial> shares = test_share(secret, params, auth, mode == "tamper-test", share_seconds);
        cout << fixed << setprecision(9);
        cout << "share " << share_seconds << " s" << endl;

        // Reconstruction validation is implemented in its own wrapper.
        vector<PartyShare> selected;
        for (int id : selected_ids) selected.push_back({id, shares.at(id)});

        // Preserve accepted CRT inputs for the new Figure 8 setup.
        ofstream accepted(directory / "accepted_crt.txt");
        accepted << sid << " " << selected.size() << "\n";
        for (const auto& input : selected)
            accepted << input.party_id << " " << json_array(input.share.coeffs) << "\n";
        accepted.close();
        if (!accepted) throw runtime_error("Cannot export accepted CRT shares");
        return 0;
    } catch (const exception& error) {
        cerr << "Error: " << error.what() << "\n";
        return 1;
    }
}
