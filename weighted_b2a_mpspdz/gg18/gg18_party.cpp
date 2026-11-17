// One local process per signer. Each process reads only its own MP-SPDZ output.
// The file mailbox is a local demonstration transport, not a network protocol.
#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <sys/stat.h>
#include "crypto-suites/crypto-commitment/commitment.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/gg18.h"

namespace fs = std::filesystem;
namespace gg = safeheron::multi_party_ecdsa::gg18;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::mpc_flow::mpc_parallel_v2::MPCContext;
using Clock = std::chrono::steady_clock;

std::string read_file(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("Cannot read " + path.string());
    return std::string(std::istreambuf_iterator<char>(input), {});
}

// Atomic publication prevents a receiver from reading an incomplete message.
void write_file(const fs::path& path, const std::string& contents) {
    fs::path temporary = path.string() + ".tmp";
    std::ofstream output(temporary, std::ios::binary);
    if (!output) throw std::runtime_error("Cannot create " + temporary.string());
    output << contents;
    output.close();
    if (!output) throw std::runtime_error("Cannot write " + temporary.string());
    fs::rename(temporary, path);
}

void require(bool ok, const std::string& message) {
    if (!ok) throw std::runtime_error(message);
}

// Retain upstream GG18 setup, including Paillier keys and proof generation.
// Replace only the local DKG contribution and its matching commitment.
// Later VSS rounds then share the supplied xi rather than a new random secret.
class ImportedRound0 : public gg::key_gen::Round0 {
    gg::key_gen::Context& context;
    BN contribution;
public:
    ImportedRound0(gg::key_gen::Context& ctx, const BN& xi)
        : context(ctx), contribution(xi) {}
    bool ComputeVerify() override {
        if (!gg::key_gen::Round0::ComputeVerify()) return false;
        const auto* curve = safeheron::curve::GetCurveParam(context.curve_type_);
        auto& party = context.local_party_;
        party.u_ = contribution;
        party.y_ = curve->g * party.u_;
        party.kgd_y_.point_ = party.y_;
        party.kgc_y_ = safeheron::commitment::CreateComWithBlind(
            party.y_, party.kgd_y_.blind_factor_);
        return true;
    }
};

// Run either GG18 key import or signing using the same round driver.
// Broadcast payloads are copied to every peer; p2p payloads go to one peer.
// Real deployment must replace this mailbox with authenticated private channels
// and a consistent broadcast mechanism. No raw xi is written to this mailbox.
void run_protocol(MPCContext& ctx, int me, int n, const fs::path& mailbox) {
    fs::create_directories(mailbox);
    const auto deadline = Clock::now() + std::chrono::minutes(20);
    auto check = [&](bool ok) {
        if (!ok) throw std::runtime_error(
            std::string("GG18 protocol failed: ") + ctx.get_last_error_info());
    };
    for (int round = 0; round < ctx.get_total_rounds(); ++round) {
        if (round == 0) {
            check(ctx.PushMessage());
        } else {
            for (int peer = 0; peer < n; ++peer) {
                if (peer == me) continue;
                fs::path path = mailbox / (std::to_string(round-1) + "-P" +
                    std::to_string(peer) + "-P" + std::to_string(me) + ".msg");
                while (!fs::exists(path)) {
                    require(Clock::now() < deadline, "Timed out waiting for a GG18 peer");
                    std::this_thread::sleep_for(std::chrono::milliseconds(20));
                }
                std::string message = read_file(path);
                auto split = message.find('\n');
                require(split != std::string::npos, "Malformed GG18 mailbox message");
                check(ctx.PushMessage(message.substr(split+1), message.substr(0, split),
                                      "P" + std::to_string(peer), round-1));
            }
        }
        require(ctx.IsCurRoundFinished(), "GG18 round did not finish");
        if (ctx.IsFinished()) break;
        std::vector<std::string> private_messages, destinations;
        std::string broadcast;
        check(ctx.PopMessages(private_messages, broadcast, destinations));
        require(private_messages.empty() || private_messages.size() == destinations.size(),
                "Unexpected GG18 outgoing message count");
        for (size_t j = 0; j < destinations.size(); ++j) {
            fs::path path = mailbox / (std::to_string(round) + "-P" +
                std::to_string(me) + "-" + destinations[j] + ".msg");
            write_file(path, broadcast + "\n" +
                       (private_messages.empty() ? "" : private_messages[j]));
        }
    }
    require(ctx.IsFinished(), "GG18 protocol did not finish");
}

int main(int argc, char* argv[]) {
    // Files created here are owner-only, even when invoked without run_local.sh.
    umask(0077);
    try {
        require(argc == 6,
            "Usage: gg18_party <session_dir> <player_index> <n> <digest_hex> <fresh_mailbox>");
        fs::path session = fs::absolute(argv[1]);
        int me = std::stoi(argv[2]);
        int n = std::stoi(argv[3]);
        std::string digest = argv[4];
        fs::path mailbox = fs::absolute(argv[5]);
        require(n >= 2 && me >= 0 && me < n, "Invalid GG18 party parameters");
        require(digest.size() == 64 && std::all_of(digest.begin(), digest.end(),
            [](unsigned char c) { return std::isxdigit(c); }),
            "Expected a 32-byte SHA-256 digest as 64 hexadecimal characters");
        const auto* curve = safeheron::curve::GetCurveParam(CurveType::SECP256K1);
        const std::string name = "P" + std::to_string(me);
        fs::path own_directory = session / "gg18" / name;
        fs::create_directories(own_directory);

        // Read exactly one output, preserving the MP-SPDZ-to-GG18 player mapping.
        std::string text = read_file(session / ("output-" + name + "-0"));
        std::regex pattern("^X_SHARE_DECIMAL=(-?[0-9]+)[ \\t\\r]*$");
        std::istringstream lines(text);
        std::string line, decimal;
        std::smatch match;
        int found = 0;
        while (std::getline(lines, line)) {
            if (std::regex_match(line, match, pattern)) {
                decimal = match[1].str();
                ++found;
            }
        }
        require(found == 1, "Expected exactly one X_SHARE_DECIMAL in own output");
        BN xi(decimal.c_str(), 10);
        xi = ((xi % curve->n) + curve->n) % curve->n;

        // Publish only a curve commitment Xi=xi*G, never the scalar xi.
        // The local runner later checks that the sum of Xi equals the GG18 key.
        CurvePoint own_public = curve->g * xi;
        // A zero additive share is valid. Use a distinct encoding for infinity.
        std::string own_x, own_y;
        if (own_public.IsInfinity()) {
            write_file(mailbox / (name + ".public"), "infinity\n");
        } else {
            own_public.x().ToHexStr(own_x);
            own_public.y().ToHexStr(own_y);
            write_file(mailbox / (name + ".public"), own_x + "\n" + own_y + "\n");
        }

        std::vector<std::string> peers;
        for (int i = 0; i < n; ++i) if (i != me) peers.push_back("P" + std::to_string(i));
        gg::key_gen::Context keygen(n);
        require(gg::key_gen::Context::CreateContext(keygen, CurveType::SECP256K1,
                    mailbox.filename().string(), n, n, name, BN(me+1), peers),
                "Cannot create GG18 key-import context");
        // Rebind only round 0. The remaining upstream VSS/proof rounds are retained.
        ImportedRound0 imported_round(keygen, xi);
        keygen.RemoveAllRounds();
        keygen.AddRound(&imported_round);
        keygen.AddRound(&keygen.round1_);
        keygen.AddRound(&keygen.round2_);
        keygen.AddRound(&keygen.round3_);
        auto started = Clock::now();
        run_protocol(keygen, me, n, mailbox / "import");
        double import_seconds = std::chrono::duration<double>(Clock::now()-started).count();
        require(keygen.sign_key_.ValidityTest(), "Imported GG18 key failed validation");
        require(!keygen.sign_key_.X_.IsInfinity(), "Zero aggregate private key cannot sign ECDSA");
        std::string key;
        require(keygen.sign_key_.ToBase64(key), "Cannot serialize own GG18 key");
        write_file(own_directory / "sign.key", key);

        // GG18 requires the complete SignKey, not the original raw additive xi.
        // Never replace this with a fresh ordinary DKG: that would change the key.
        gg::sign::Context signing(n);
        require(gg::sign::Context::CreateContext(signing, key, BN(digest.c_str(), 16)),
                "Cannot create GG18 signing context");
        started = Clock::now();
        run_protocol(signing, me, n, mailbox / "sign");
        double signing_seconds = std::chrono::duration<double>(Clock::now()-started).count();
        require(safeheron::curve::ecdsa::VerifyPublicKey(keygen.sign_key_.X_,
                    CurveType::SECP256K1, BN(digest.c_str(),16), signing.r_, signing.s_, signing.v_),
                "ECDSA signature verification failed");
        std::string r, s, pub_x, pub_y;
        signing.r_.ToHexStr(r);
        signing.s_.ToHexStr(s);
        keygen.sign_key_.X_.x().ToHexStr(pub_x);
        keygen.sign_key_.X_.y().ToHexStr(pub_y);
        // Only public signature information is written to this JSON file.
        write_file(own_directory / "signature.json",
            "{\"digest_hex\":\"" + digest + "\",\"r_hex\":\"" + r +
            "\",\"s_hex\":\"" + s + "\",\"recovery_id\":" + std::to_string(signing.v_) +
            ",\"public_x_hex\":\"" + pub_x + "\",\"public_y_hex\":\"" + pub_y +
            "\",\"verified\":true,\"import_seconds\":" + std::to_string(import_seconds) +
            ",\"sign_seconds\":" + std::to_string(signing_seconds) + "}\n");
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "GG18 error: " << error.what() << "\n";
        return 1;
    }
}
