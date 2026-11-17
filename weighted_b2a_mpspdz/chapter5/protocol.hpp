#pragma once
#include <gmpxx.h>
#include <map>

namespace ch5 {
using Scalar = mpz_class;
using Clock = chrono::steady_clock;
inline double elapsed(Clock::time_point t) {
  return chrono::duration<double>(Clock::now() - t).count();
}
inline Scalar mod(Scalar x, const Scalar &q) {
  x %= q;
  return x < 0 ? x + q : x;
}
inline AuthElement ax(AuthElement a, const AuthElement &b) {
  for (int k = 0; k < 16; k++)
    a[k] ^= b[k];
  return a;
}
inline vector<int> bits(const Polynomial &p, int n) {
  if (p.degree() >= n)
    throw runtime_error("Polynomial width mismatch");
  auto v = p.coeffs;
  v.resize(n);
  return v;
}
inline AuthVector transform(const AuthVector &a, const Polynomial &multiplier,
                            const Polynomial &modulus) {
  AuthVector out(a.size() + multiplier.coeffs.size() - 1);
  for (size_t k = 0; k < a.size(); k++)
    for (size_t l = 0; l < multiplier.coeffs.size(); l++)
      if (multiplier.coeffs[l])
        out[k + l] = ax(out[k + l], a[k]);
  return auth_mod(out, modulus);
}
struct AuthBits {
  vector<int> value;           // Owner-local coefficients, fixed width.
  vector<AuthVector> tag, key; // tag[j] held by owner; key[j] held ONLY by
                               // verifier j in deployment.
};
struct DaBits {
  vector<AuthBits> binary;
  vector<vector<Scalar>> a, g;
  bool used = false;
};
struct Preprocessing {
  vector<AuthElement> delta;
  vector<Scalar> alpha;
  vector<AuthBits> input_masks;
  DaBits zero, b2a;
  Scalar q;
  string sid;
  bool masks_used = false;
};
// This harness gathers private role files to simulate online rounds locally.
// It is not a distributed transport or a privacy-preserving deployment.
inline vector<map<string, Scalar>> read_roles(const filesystem::path &dir,
                                              int n, const Scalar &q) {
  vector<map<string, Scalar>> out(n);
  for (int i = 0; i < n; i++) {
    ifstream f(dir / ("role-" + to_string(i) + ".txt"));
    if (!f)
      throw runtime_error("Missing private preprocessing role file");
    string line;
    while (getline(f, line)) {
      auto eq = line.find('=');
      if (eq == string::npos)
        continue;
      string name = line.substr(0, eq), raw = line.substr(eq + 1);
      if (raw.empty() || raw.find_first_not_of("-0123456789") != string::npos)
        throw runtime_error("Invalid preprocessing scalar");
      Scalar x(raw);
      if (x <= -q || x >= q)
        throw runtime_error("Noncanonical MPC output");
      if (!out[i].emplace(name, mod(x, q)).second)
        throw runtime_error("Duplicate preprocessing field");
    }
  }
  return out;
}
inline Preprocessing load_preprocessing(const filesystem::path &dir,
                                        const vector<int> &degree, int h,
                                        int d0, const Scalar &q,
                                        const string &sid) {
  if (!filesystem::exists(dir / "READY") ||
      filesystem::exists(dir / "CONSUMED"))
    throw runtime_error("Preprocessing missing or consumed");
  ifstream manifest(dir / "READY");
  string saved_sid, saved_q;
  manifest >> saved_sid >> saved_q;
  if (saved_sid != sid || saved_q != q.get_str())
    throw runtime_error("Preprocessing context mismatch");
  // Atomic one-shot claim. Never retry with the same masks after an abort.
  filesystem::rename(dir / "READY", dir / "CONSUMED");
  int n = degree.size(),
      chunk = min(32, int(mpz_sizeinbase(q.get_mpz_t(), 2)) - 1);
  auto roles = read_roles(dir, n, q);
  auto get = [&](int i, const string &name) -> Scalar {
    auto it = roles[i].find(name);
    if (it == roles[i].end())
      throw runtime_error("Missing preprocessing field: " + name);
    return it->second;
  };
  auto field = [&](int i, const string &name) {
    Scalar packed = 0;
    for (int off = 0; off < 128; off += chunk) {
      Scalar x = get(i, name + "_" + to_string(off));
      if (x >= (Scalar(1) << min(chunk, 128 - off)))
        throw runtime_error("Invalid tag chunk");
      packed |= x << off;
    }
    AuthElement a{};
    for (int k = 0; k < 16; k++)
      a[k] = static_cast<unsigned char>(
          Scalar((packed >> (8 * k)) & 255).get_ui());
    return a;
  };
  auto auth = [&](const string &name, int i, int length) {
    AuthBits a;
    a.value.resize(length);
    a.tag.resize(n);
    a.key.resize(n);
    for (int k = 0; k < length; k++) {
      Scalar b = get(i, name + "_B_" + to_string(k));
      if (b != 0 && b != 1)
        throw runtime_error("Nonbinary mask");
      a.value[k] = b.get_si();
    }
    for (int j = 0; j < n; j++)
      if (j != i)
        for (int k = 0; k < length; k++) {
          a.tag[j].push_back(
              field(i, name + "_M_" + to_string(j) + "_" + to_string(k)));
          a.key[j].push_back(
              field(j, name + "_K_" + to_string(i) + "_" + to_string(k)));
        }
    return a;
  };
  Preprocessing p;
  p.q = q;
  p.sid = sid;
  for (int i = 0; i < n; i++) {
    p.delta.push_back(field(i, "DELTA"));
    p.alpha.push_back(get(i, "ALPHA"));
    p.input_masks.push_back(auth("R", i, degree[i]));
  }
  auto dabit = [&](const string &name, int len) {
    DaBits d;
    d.a.resize(n);
    d.g.resize(n);
    for (int i = 0; i < n; i++) {
      d.binary.push_back(auth(name, i, len));
      for (int k = 0; k < len; k++) {
        d.a[i].push_back(get(i, name + "_A_" + to_string(k)));
        d.g[i].push_back(get(i, name + "_G_" + to_string(k)));
      }
    }
    return d;
  };
  p.zero = dabit("Z", h);
  p.b2a = dabit("B", d0);
  return p;
}
inline void verify(const AuthBits &a, int owner, const Preprocessing &p) {
  for (size_t j = 0; j < p.delta.size(); j++)
    if (int(j) != owner) {
      if (a.tag[j].size() != a.value.size() ||
          a.key[j].size() != a.value.size())
        throw runtime_error("MAC width mismatch");
      for (size_t k = 0; k < a.value.size(); k++) {
        if (a.value[k] != 0 && a.value[k] != 1)
          throw runtime_error("Nonbinary opening");
        auto expected = a.tag[j][k];
        if (a.value[k])
          expected = ax(expected, p.delta[j]);
        if (CRYPTO_memcmp(expected.data(), a.key[j][k].data(), 16))
          throw runtime_error("BDOZ MAC check failed");
      }
    }
}
inline AuthBits linear(const AuthBits &a, const Polynomial &multiplier,
                       const Polynomial &modulus, int owner) {
  AuthBits b;
  b.value = bits(Polynomial(a.value).mul(multiplier).mod_poly(modulus),
                 modulus.degree());
  b.tag.resize(a.tag.size());
  b.key.resize(a.key.size());
  for (size_t j = 0; j < a.tag.size(); j++)
    if (int(j) != owner) {
      b.tag[j] = transform(a.tag[j], multiplier, modulus);
      b.key[j] = transform(a.key[j], multiplier, modulus);
    }
  return b;
}
inline AuthBits slice(const AuthBits &a, int offset, int owner) {
  AuthBits b;
  b.value.assign(a.value.begin() + offset, a.value.end());
  b.tag.resize(a.tag.size());
  b.key.resize(a.key.size());
  for (size_t j = 0; j < a.tag.size(); j++)
    if (int(j) != owner) {
      b.tag[j].assign(a.tag[j].begin() + offset, a.tag[j].end());
      b.key[j].assign(a.key[j].begin() + offset, a.key[j].end());
    }
  return b;
}
inline AuthBits plus(AuthBits a, const AuthBits &b, int owner) {
  if (a.value.size() != b.value.size())
    throw runtime_error("Authenticated vector width mismatch");
  for (size_t k = 0; k < a.value.size(); k++) {
    a.value[k] ^= b.value[k];
    for (size_t j = 0; j < a.tag.size(); j++)
      if (int(j) != owner) {
        a.tag[j][k] = ax(a.tag[j][k], b.tag[j][k]);
        a.key[j][k] = ax(a.key[j][k], b.key[j][k]);
      }
  }
  return a;
}
inline array<unsigned char, 32>
commitment(const string &sid, const string &purpose, int party,
           const Scalar &residual, const array<unsigned char, 32> &salt) {
  string data = "weighted-crt-ch5-v1|" + sid + "|" + purpose + "|" +
                to_string(party) + "|" + residual.get_str() + "|";
  data.append(reinterpret_cast<const char *>(salt.data()), salt.size());
  array<unsigned char, 32> hash{};
  if (!SHA256(reinterpret_cast<const unsigned char *>(data.data()), data.size(),
              hash.data()))
    throw runtime_error("SHA256 failed");
  return hash;
}
inline Scalar spdz_open(const vector<Scalar> &x, const vector<Scalar> &mu,
                        const Preprocessing &p, const string &purpose) {
  int n = x.size();
  Scalar opened = 0;
  for (auto &v : x)
    opened = mod(opened + v, p.q);
  vector<Scalar> residual(n);
  vector<array<unsigned char, 32>> salts(n), commits(n);
  // Phase 1: freeze every commitment before revealing ANY residual.
  for (int i = 0; i < n; i++) {
    residual[i] = mod(mu[i] - p.alpha[i] * opened, p.q);
    if (RAND_bytes(salts[i].data(), 32) != 1)
      throw runtime_error("RAND failed");
    commits[i] = commitment(p.sid, purpose, i, residual[i], salts[i]);
  }
  // Phase 2: simulated consistent broadcast of all openings.
  Scalar sum = 0;
  for (int i = 0; i < n; i++) {
    auto check = commitment(p.sid, purpose, i, residual[i], salts[i]);
    if (CRYPTO_memcmp(check.data(), commits[i].data(), 32))
      throw runtime_error("Commitment mismatch");
    sum = mod(sum + residual[i], p.q);
  }
  if (sum != 0)
    throw runtime_error("SPDZ MAC check failed");
  return opened;
}
inline vector<AuthBits> generate_zero(Preprocessing &p) {
  if (p.zero.used)
    throw runtime_error("Zero daBits already consumed");
  p.zero.used = true;
  auto zero = p.zero.binary;
  int n = zero.size(), len = zero[0].value.size();
  // Figure 7 lines 1--11: open arithmetic halves, update only owner 0's bit
  // and verifier keys; tags remain unchanged.
  for (int k = 0; k < len; k++) {
    vector<Scalar> a(n), g(n);
    for (int i = 0; i < n; i++) {
      a[i] = p.zero.a[i][k];
      g[i] = p.zero.g[i][k];
    }
    Scalar b = spdz_open(a, g, p, "zero-" + to_string(k));
    if (b != 0 && b != 1)
      throw runtime_error("Invalid daBit arithmetic opening");
    if (b == 1) {
      zero[0].value[k] ^= 1;
      for (int j = 1; j < n; j++)
        zero[0].key[j][k] = ax(zero[0].key[j][k], p.delta[j]);
    }
  }
  return zero;
}
namespace figure8 {
struct State {
  Parameters params;
  vector<Polynomial> lambda;
  Polynomial M;
  vector<AuthBits> shares, zero;
  bool converted = false;
};
inline State setup(const vector<PartyShare> &input, const Parameters &params,
                   Preprocessing &pre) {
  // Figure 8 lines 1--9. Offline input authentication assumes accepted Ch4
  // shares.
  if (pre.masks_used)
    throw runtime_error("Input masks already consumed");
  pre.masks_used = true;
  State s;
  s.params = params;
  s.M = Polynomial({1});
  long long weight = 0;
  set<int> ids;
  for (auto &in : input) {
    if (in.party_id < 0 || size_t(in.party_id) >= params.parties.size() ||
        !ids.insert(in.party_id).second)
      throw runtime_error("Invalid selected IDs");
    auto &party = params.parties[in.party_id];
    weight += party.weight;
    s.M = s.M.mul(party.modulus);
  }
  if (weight < 1LL * params.reconstruction_threshold + params.privacy_threshold)
    throw runtime_error("Selected weight is below T+t");
  if (input.size() != pre.input_masks.size())
    throw runtime_error("Participant mapping mismatch");
  for (size_t i = 0; i < input.size(); i++) {
    auto &mi = params.parties[input[i].party_id].modulus;
    auto quotient = s.M.div_rem(mi).first;
    s.lambda.push_back(quotient.mul(quotient.inverse_mod(mi)));
    AuthBits a = pre.input_masks[i];
    auto actual = bits(input[i].share, mi.degree());
    for (size_t k = 0; k < actual.size(); k++) {
      int e = actual[k] ^ a.value[k];
      if (e)
        for (size_t j = 0; j < input.size(); j++)
          if (j != i)
            a.key[j][k] = ax(a.key[j][k], pre.delta[j]);
    }
    a.value = actual;
    s.shares.push_back(a);
  }
  s.zero = generate_zero(pre);
  return s;
}
inline vector<AuthBits> convert(State &s, const Preprocessing &pre) {
  if (s.converted)
    throw runtime_error("Figure 8 conversion already used");
  s.converted = true;
  vector<AuthBits> sigma;
  vector<int> sum(s.M.degree() - s.params.reconstruction_threshold);
  for (size_t i = 0; i < s.shares.size(); i++) {
    sigma.push_back(
        linear(s.shares[i], s.lambda[i], s.M, i)); // lines 12,16--17
    auto c = plus(slice(sigma.back(), s.params.reconstruction_threshold, i),
                  s.zero[i], i); // 13,18--19
    verify(c, i, pre);
    for (size_t k = 0; k < sum.size(); k++)
      sum[k] ^= c.value[k]; // 20
  }
  if (any_of(sum.begin(), sum.end(), [](int b) { return b != 0; }))
    throw runtime_error("Degree consistency check failed"); // 22
  vector<AuthBits> u;
  for (size_t i = 0; i < sigma.size(); i++)
    u.push_back(linear(sigma[i], Polynomial({1}), s.params.m0, i));
  return u; // 23--25
}
inline Polynomial reconstruction(const vector<AuthBits> &u,
                                 const Preprocessing &p) {
  vector<int> value(u.at(0).value.size());
  for (size_t i = 0; i < u.size(); i++) {
    verify(u[i], i, p);
    if (u[i].value.size() != value.size())
      throw runtime_error("Reconstruction width mismatch");
    for (size_t k = 0; k < value.size(); k++)
      value[k] ^= u[i].value[k];
  }
  return Polynomial(value); // 29--34
}
inline vector<AuthBits> test_convert(State &s, const Preprocessing &p,
                                     double &seconds) {
  auto t = Clock::now();
  auto u = convert(s, p);
  seconds = elapsed(t);
  return u;
}
inline void test_reconstruction(const vector<AuthBits> &u,
                                const Preprocessing &p,
                                const Polynomial &expected, double &seconds) {
  auto t = Clock::now();
  auto recovered = reconstruction(u, p);
  seconds = elapsed(t);
  if (recovered.coeffs != expected.coeffs)
    throw runtime_error("Figure 8 reconstruction test failed");
}
} // namespace figure8
namespace figure9 {
struct State {
  vector<AuthBits> u;
  DaBits masks;
  bool used = false;
};
struct Output {
  vector<Scalar> x, mu;
};
inline State setup(const vector<AuthBits> &u, Preprocessing &pre) {
  // Figure 9 lines 1--15: retain Figure 8 authentication and SAME Delta keys.
  if (pre.b2a.used)
    throw runtime_error("B2A daBits already consumed");
  pre.b2a.used = true;
  if (u.size() != pre.b2a.binary.size())
    throw runtime_error("B2A participant mismatch");
  for (size_t i = 0; i < u.size(); i++)
    if (u[i].value.size() != pre.b2a.binary[i].value.size())
      throw runtime_error("B2A width mismatch");
  return {u, pre.b2a, false};
}
inline Output convert(State &s, const Preprocessing &p) {
  if (s.used)
    throw runtime_error("Figure 9 conversion already used");
  s.used = true;
  int n = s.u.size(), d0 = s.u.at(0).value.size();
  vector<int> c(d0);
  for (int i = 0; i < n; i++) {
    auto ci = plus(s.u[i], s.masks.binary[i], i);
    verify(ci, i, p);
    for (int k = 0; k < d0; k++)
      c[k] ^= ci.value[k];
  } // 18--23
  Output out;
  out.x.resize(n);
  out.mu.resize(n);
  for (int i = 0; i < n; i++) {
    Scalar power = 1;
    for (int k = 0; k < d0; k++) {
      Scalar e =
          mod((i == 0 ? c[k] : 0) + (1 - 2 * c[k]) * s.masks.a[i][k], p.q);
      Scalar eta = mod((1 - 2 * c[k]) * s.masks.g[i][k] + p.alpha[i] * c[k],
                       p.q); // 24--25
      out.x[i] = mod(out.x[i] + power * e, p.q);
      out.mu[i] = mod(out.mu[i] + power * eta, p.q);
      power = mod(2 * power, p.q); // 27--28
    }
  }
  return out;
}
inline Scalar reconstruction(const Output &out, const Preprocessing &p) {
  return spdz_open(out.x, out.mu, p, "figure9-reconstruction");
} // 31--35
inline Output test_convert(State &s, const Preprocessing &p, double &seconds) {
  auto t = Clock::now();
  auto out = convert(s, p);
  seconds = elapsed(t);
  return out;
}
inline void test_reconstruction(const Output &out, const Preprocessing &p,
                                const Polynomial &secret, double &seconds) {
  Scalar expected = 0;
  for (int k = secret.degree(); k >= 0; k--)
    expected = mod(2 * expected + secret.coeffs[k], p.q);
  auto t = Clock::now();
  Scalar recovered = reconstruction(out, p);
  seconds = elapsed(t);
  if (recovered != expected)
    throw runtime_error("Figure 9 reconstruction test failed");
}
} // namespace figure9
} // namespace ch5
