// Chapter 4 is preserved in chapter4.hpp; Chapter 5 is in
// chapter5/protocol.hpp.
#include "chapter4.hpp"
#include "chapter5/protocol.hpp"
using namespace ch5;
static Polynomial read_poly(istream &f) {
  string s;
  f >> s;
  if (!f || s.size() < 3 || s.front() != '[' || s.back() != ']')
    throw runtime_error("Invalid polynomial encoding");
  return Polynomial(parse_list(s.substr(1, s.size() - 2)));
}
int main(int argc, char **argv) {
  umask(0077);
  // Backward-compatible Section 4.3 prepare/share interface used by
  // run_share.py.
  if (argc == 9)
    return chapter4_entry(argc, argv);
  try {
    if (argc < 3)
      throw runtime_error("Use run_local.sh");
    string command = argv[1];
    filesystem::path dir = argv[2];
    if (command == "prepare") {
      if (argc != 11)
        throw runtime_error("prepare dir T t min_bits weights ids secret q "
                            "fixture|authenticated");
      int T = stoi(argv[3]), t = stoi(argv[4]), min_bits = stoi(argv[5]);
      auto weights = parse_list(argv[6]), ids = parse_list(argv[7]);
      Polynomial secret(parse_list(argv[8]));
      Scalar q(argv[9]);
      string source = argv[10];
      if (T <= t || t < 0 || q <= 65536 ||
          mpz_probab_prime_p(q.get_mpz_t(), 40) == 0)
        throw runtime_error("Invalid thresholds or field");
      // Reject ONLY the requested negative category with a distinct exit code.
      long long w = 0;
      set<int> seen;
      for (int id : ids) {
        if (id < 0 || size_t(id) >= weights.size() || !seen.insert(id).second)
          throw runtime_error("Invalid party IDs");
        w += weights[id];
      }
      if (w < T)
        throw runtime_error("Selected weight below T");
      if (w < 1LL * T + t) {
        cout << "EXPECTED_WEIGHT_REJECTION: T <= selected_weight < T+t\n";
        return 42;
      }
      if (ids.size() < 2)
        throw runtime_error("At least two selected parties required");
      filesystem::create_directories(dir);
      if (filesystem::exists(dir / "state.txt"))
        throw runtime_error("Use a fresh session directory");
      auto started = Clock::now();
      Parameters p;
      string sid;
      vector<PartyShare> shares;
      if (source == "fixture") {
        p = generate_weighted_parameters(weights, T, t, min_bits);
        if (secret.degree() >= p.m0.degree())
          throw runtime_error("Secret too large");
        // Honest Chapter 4 inputs for Chapter 5-only tests; NOT a VSS
        // implementation.
        Polynomial f =
            secret.add(Polynomial(random_bits(p.privacy_threshold)).mul(p.m0));
        for (int id : ids)
          shares.push_back({id, f.mod_poly(p.parties[id].modulus)});
        auto bytes = random_bits(256);
        for (int b : bytes)
          sid += char('0' + b);
      } else if (source == "authenticated") {
        ifstream conf(dir / "ch4/parameters.txt");
        int n;
        conf >> sid >> p.scale >> p.reconstruction_threshold >>
            p.privacy_threshold >> n;
        if (!conf || n != int(weights.size()) || p.scale <= 0 ||
            p.reconstruction_threshold != 1LL * p.scale * T ||
            p.privacy_threshold != 1LL * p.scale * t)
          throw runtime_error("Chapter 4 context mismatch");
        p.field_modulus = 2;
        p.m0 = read_poly(conf);
        for (int i = 0; i < n; i++) {
          auto mi = read_poly(conf);
          if (mi.degree() != 1LL * p.scale * weights[i])
            throw runtime_error("Chapter 4 degree mismatch");
          p.parties.push_back({i, mi.degree(), mi});
        }
        ifstream accepted(dir / "ch4/accepted_crt.txt");
        string saved;
        int count;
        accepted >> saved >> count;
        if (saved != sid || count != int(ids.size()))
          throw runtime_error("Accepted-share context mismatch");
        for (int id : ids) {
          int actual;
          accepted >> actual;
          auto share = read_poly(accepted);
          if (actual != id)
            throw runtime_error("Accepted-share ID mismatch");
          shares.push_back({id, share});
        }
        if (p.m0.degree() < int(mpz_sizeinbase(Scalar(q - 1).get_mpz_t(), 2)))
          throw runtime_error("Secret domain too small for q");
      } else
        throw runtime_error("Unknown input mode");
      if (p.m0.degree() < int(mpz_sizeinbase(Scalar(q - 1).get_mpz_t(), 2)))
        throw runtime_error(
            "Paper requires d0 >= ceil(log2 q); increase min_bits");
      double preparation = elapsed(started);
      int d = 0;
      vector<int> degrees;
      for (int id : ids) {
        degrees.push_back(p.parties[id].weight);
        d += p.parties[id].weight;
      }
      ofstream state(dir / "state.txt");
      state << sid << " " << q << " " << p.scale << " "
            << p.reconstruction_threshold << " " << p.privacy_threshold << " "
            << p.parties.size() << " " << shares.size() << "\n";
      state << json_array(p.m0.coeffs) << "\n"
            << json_array(secret.coeffs) << "\n";
      for (auto &party : p.parties)
        state << party.id << " " << party.weight << " "
              << json_array(party.modulus.coeffs) << "\n";
      for (auto &s : shares)
        state << s.party_id << " " << json_array(s.share.coeffs) << "\n";
      state.close();
      if (!state)
        throw runtime_error("State write failed");
      ofstream context(dir / "context.json");
      context << setprecision(17) << "{\"sid\":\"" << sid << "\",\"q\":\"" << q
              << "\",\"degrees\":" << json_array(degrees)
              << ",\"h\":" << d - p.reconstruction_threshold
              << ",\"d0\":" << p.m0.degree() << ",\"input_mode\":\"" << source
              << "\",\"input_prepare_seconds\":" << preparation << "}\n";
      return 0;
    }
    if (command != "execute" || argc != 3)
      throw runtime_error("Unknown command");
    ifstream f(dir / "state.txt");
    Parameters p;
    string sid;
    Scalar q;
    int n, m;
    f >> sid >> q >> p.scale >> p.reconstruction_threshold >>
        p.privacy_threshold >> n >> m;
    if (!f || n < 2 || m < 2 || m > n)
      throw runtime_error("Invalid session state");
    p.field_modulus = 2;
    p.m0 = read_poly(f);
    Polynomial secret = read_poly(f);
    for (int i = 0; i < n; i++) {
      int id, w;
      f >> id >> w;
      auto mi = read_poly(f);
      if (id != i || mi.degree() != w)
        throw runtime_error("Invalid party record");
      p.parties.push_back({id, w, mi});
    }
    vector<PartyShare> shares;
    vector<int> degrees;
    int d = 0;
    for (int i = 0; i < m; i++) {
      int id;
      f >> id;
      auto share = read_poly(f);
      if (id < 0 || id >= n)
        throw runtime_error("Invalid selected ID");
      shares.push_back({id, share});
      degrees.push_back(p.parties[id].weight);
      d += degrees.back();
    }
    auto load_start = Clock::now();
    auto pre = load_preprocessing(dir / "preprocessing", degrees,
                                  d - p.reconstruction_threshold, p.m0.degree(),
                                  q, sid);
    double load_s = elapsed(load_start);
    auto start8 = Clock::now();
    auto s8 = figure8::setup(shares, p, pre);
    double setup8 = elapsed(start8), conv8, recon8;
    auto u = figure8::test_convert(s8, pre, conv8);
    auto start9 = Clock::now();
    auto s9 = figure9::setup(u, pre);
    double setup9 = elapsed(start9), conv9, recon9;
    auto result = figure9::test_convert(s9, pre, conv9);
    // Reconstruction helpers are retained but never called on this path.
    // Reconstruction deliberately not invoked.
    recon8 = 0;
    recon9 = 0;
    // Owner-separated outputs retain authentication; no automatic
    // unauthenticated GG18 import.
    for (int i = 0; i < m; i++) {
      ofstream out(dir / ("arithmetic-P" + to_string(i) + ".txt"));
      out << "sid=" << sid << "\nparty_id=" << shares[i].party_id << "\nq=" << q
          << "\nx=" << result.x[i] << "\nmu=" << result.mu[i]
          << "\nalpha=" << pre.alpha[i] << "\n";
      if (!out)
        throw runtime_error("Output write failed");
    }
    ofstream metrics(dir / "online_metrics.json");
    metrics << setprecision(17) << "{\"load_seconds\":" << load_s
            << ",\"figure8_setup\":" << setup8
            << ",\"figure8_test_convert\":" << conv8
            << ",\"figure8_test_reconstruction\":" << recon8
            << ",\"figure9_setup\":" << setup9
            << ",\"figure9_test_convert\":" << conv9
            << ",\"figure9_test_reconstruction\":" << recon9
            << ",\"convention_online\":" << conv8 + conv9 << "}\n";
    if (!metrics)
      throw runtime_error("Metric write failed");
    return 0;
  } catch (const exception &e) {
    cerr << "Error: " << e.what() << "\n";
    return 1;
  }
}
