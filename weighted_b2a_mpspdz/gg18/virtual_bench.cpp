// Single-process GG18 virtualization baseline with in-memory message delivery.
#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "crypto-suites/crypto-curve/curve.h"
#include "multi-party-sig/multi-party-ecdsa/gg18/gg18.h"

namespace gg = safeheron::multi_party_ecdsa::gg18;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::mpc_flow::mpc_parallel_v2::MPCContext;
using Clock = std::chrono::steady_clock;

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

struct VirtualParty {
    std::string id;
    int index;
};

struct Registry {
    int threshold;
    int total_weight;
    std::vector<std::vector<VirtualParty>> owners;
    CurvePoint public_key;
    std::string group_id;
};

using KeyBundle = std::vector<gg::SignKey>;
struct KeygenResult {
    Registry registry;
    std::vector<KeyBundle> owner_keys;
};

struct Message {
    std::string sender;
    std::string broadcast;
    std::string private_payload;
};

using Contexts = std::map<std::string, MPCContext*>;

void run_rounds(const Contexts& contexts) {
    std::map<std::string, std::vector<Message>> inbox;
    const int rounds = contexts.begin()->second->get_total_rounds();
    for (int round = 0; round < rounds; ++round) {
        std::map<std::string, std::vector<Message>> next_inbox;
        for (const auto& [id, context] : contexts) {
            auto check = [&](bool ok) {
                if (!ok) throw std::runtime_error(
                    "GG18 round " + std::to_string(round) + ", " + id + ": " +
                    context->get_last_error_info());
            };
            if (round == 0) {
                check(context->PushMessage());
            } else {
                const auto& messages = inbox.at(id);
                require(messages.size() == contexts.size() - 1,
                        "Wrong number of incoming GG18 messages");
                for (const auto& message : messages) {
                    check(context->PushMessage(message.private_payload, message.broadcast,
                                               message.sender, round - 1));
                }
            }

            require(context->IsCurRoundFinished(), "Incomplete GG18 round");
            if (round == rounds - 1) {
                require(context->IsFinished(), "Incomplete GG18 protocol");
                continue;
            }

            std::vector<std::string> private_messages, recipients;
            std::string broadcast;
            check(context->PopMessages(private_messages, broadcast, recipients));
            require(private_messages.empty() || private_messages.size() == recipients.size(),
                    "Wrong number of outgoing GG18 messages");
            std::set<std::string> sent;
            for (size_t j = 0; j < recipients.size(); ++j) {
                const auto& recipient = recipients[j];
                require(recipient != id && contexts.count(recipient) && sent.insert(recipient).second,
                        "Invalid GG18 message recipient");
                next_inbox[recipient].push_back(
                    {id, broadcast, private_messages.empty() ? "" : private_messages[j]});
            }
        }
        inbox = std::move(next_inbox);
    }
}

std::string hex(const unsigned char* bytes, size_t count) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (size_t i = 0; i < count; ++i) out << std::setw(2) << unsigned(bytes[i]);
    return out.str();
}

KeygenResult VirtualKeyGen(const std::vector<int>& weights, int threshold) {
    KeygenResult result{{threshold, 0, {}, CurvePoint(), {}}, {}};
    auto& registry = result.registry;
    for (int weight : weights) {
        require(weight > 0 && weight <= std::numeric_limits<int>::max() - registry.total_weight,
                "Invalid weight or total weight overflow");
        registry.total_weight += weight;
    }
    require(threshold >= 2 && threshold <= registry.total_weight,
            "Expected 2 <= threshold <= total weight");

    std::vector<std::string> all_ids;
    for (int weight : weights) {
        auto& owner = registry.owners.emplace_back();
        for (int j = 0; j < weight; ++j) {
            const int index = static_cast<int>(all_ids.size()) + 1;
            const auto& id = all_ids.emplace_back("V" + std::to_string(index));
            owner.push_back({id, index});
        }
    }

    std::array<unsigned char, 16> session{};
    require(RAND_bytes(session.data(), session.size()) == 1, "Cannot generate key group ID");
    registry.group_id = hex(session.data(), session.size());
    std::map<std::string, std::unique_ptr<gg::key_gen::Context>> keygens;
    Contexts contexts;
    for (const auto& owner : registry.owners) {
        for (const auto& party : owner) {
            std::vector<std::string> peers;
            for (const auto& id : all_ids) {
                if (id != party.id) peers.push_back(id);
            }
            auto context = std::make_unique<gg::key_gen::Context>(registry.total_weight);
            require(gg::key_gen::Context::CreateContext(
                        *context, CurveType::SECP256K1, registry.group_id, threshold,
                        registry.total_weight, party.id, BN(party.index), peers),
                    "Cannot create GG18 KeyGen context for " + party.id);
            contexts.emplace(party.id, context.get());
            keygens.emplace(party.id, std::move(context));
        }
    }
    run_rounds(contexts);
    registry.public_key = keygens.at(all_ids.front())->sign_key_.X_;
    require(!registry.public_key.IsInfinity(), "Invalid aggregate public key");
    for (const auto& owner : registry.owners) {
        auto& bundle = result.owner_keys.emplace_back();
        for (const auto& party : owner) {
            auto& key = keygens.at(party.id)->sign_key_;
            require(key.X_ == registry.public_key && key.ValidityTest(),
                    "Invalid GG18 key for " + party.id);
            bundle.push_back(std::move(key));
        }
    }
    return result;
}

struct Signature {
    BN r;
    BN s;
    uint32_t recovery_id;
    size_t virtual_signers;
};

Signature VirtualSign(const Registry& registry,
                      const std::vector<std::pair<int, const KeyBundle*>>& selected_owners,
                      const std::string& message) {
    std::set<int> real_ids;
    std::vector<std::string> selected_ids;
    std::map<std::string, const gg::SignKey*> keys;
    for (const auto& [owner_id, bundle] : selected_owners) {
        require(owner_id > 0 && static_cast<size_t>(owner_id) <= registry.owners.size() &&
                    real_ids.insert(owner_id).second,
                "Unknown or duplicate real participant ID");
        const auto& expected = registry.owners.at(owner_id - 1);
        require(bundle && bundle->size() == expected.size(),
                "Each real participant must provide its complete key bundle");
        std::map<std::string, int> expected_indices;
        for (const auto& party : expected) expected_indices.emplace(party.id, party.index);
        for (const auto& key : *bundle) {
            const auto& id = key.local_party_.party_id_;
            const auto it = expected_indices.find(id);
            require(it != expected_indices.end() && key.local_party_.index_ == BN(it->second) &&
                        key.X_ == registry.public_key && key.workspace_id_ == registry.group_id &&
                        key.threshold_ == static_cast<unsigned>(registry.threshold) &&
                        key.n_parties_ == static_cast<unsigned>(registry.total_weight) &&
                        keys.emplace(id, &key).second,
                    "Invalid or duplicate GG18 key in real participant bundle");
        }
        for (const auto& party : expected) selected_ids.push_back(party.id);
    }
    require(selected_ids.size() >= static_cast<size_t>(registry.threshold),
            "Selected real participants have insufficient total weight");

    std::array<unsigned char, SHA256_DIGEST_LENGTH> hash{};
    require(SHA256(reinterpret_cast<const unsigned char*>(message.data()),
                   message.size(), hash.data()) != nullptr, "Cannot hash message");
    const auto digest_hex = hex(hash.data(), hash.size());
    const BN digest(digest_hex.c_str(), 16);
    std::map<std::string, std::unique_ptr<gg::sign::Context>> signers;
    Contexts contexts;
    for (const auto& id : selected_ids) {
        std::string full_key, trimmed_key;
        require(keys.at(id)->ToBase64(full_key), "Cannot serialize GG18 key for " + id);
        require(gg::trim_sign_key(trimmed_key, full_key, selected_ids),
                "Cannot trim GG18 key for " + id);
        auto context = std::make_unique<gg::sign::Context>(static_cast<int>(selected_ids.size()));
        require(gg::sign::Context::CreateContext(*context, trimmed_key, digest),
                "Cannot create GG18 signing context for " + id);
        contexts.emplace(id, context.get());
        signers.emplace(id, std::move(context));
    }
    run_rounds(contexts);

    const auto& first = *signers.at(selected_ids.front());
    for (const auto& [id, signer] : signers) {
        require(signer->r_ == first.r_ && signer->s_ == first.s_ && signer->v_ == first.v_,
                "GG18 signatures disagree at " + id);
    }
    require(safeheron::curve::ecdsa::VerifyPublicKey(registry.public_key, CurveType::SECP256K1,
                digest, first.r_, first.s_, first.v_), "ECDSA signature verification failed");
    return {first.r_, first.s_, first.v_, selected_ids.size()};
}

int positive_integer(const std::string& text) {
    int value = 0;
    const auto* end = text.data() + text.size();
    const auto parsed = std::from_chars(text.data(), end, value);
    require(parsed.ec == std::errc{} && parsed.ptr == end && value > 0,
            "Expected a positive integer: " + text);
    return value;
}

std::vector<int> integer_list(const std::string& text) {
    require(!text.empty() && text.back() != ',', "Expected a comma-separated list of integers");
    std::vector<int> values;
    std::istringstream input(text);
    std::string part;
    while (std::getline(input, part, ',')) values.push_back(positive_integer(part));
    return values;
}

int main(int argc, char* argv[]) {
    try {
        require(argc == 5,
                "Usage: gg18_virtual_bench <weights_csv> <threshold> <real_ids_csv> <message>");
        const auto weights = integer_list(argv[1]);
        const int threshold = positive_integer(argv[2]);
        const auto owner_ids = integer_list(argv[3]);
        auto started = Clock::now();
        const auto keygen = VirtualKeyGen(weights, threshold);
        const auto initialization_seconds = std::chrono::duration<double>(Clock::now() - started);
        std::cout << std::fixed << std::setprecision(9)
                  << "initialization_seconds=" << initialization_seconds.count() << '\n'
                  << "real_parties=" << weights.size() << '\n'
                  << "total_virtual_parties=" << keygen.registry.total_weight << '\n';

        std::vector<std::pair<int, const KeyBundle*>> selected;
        for (int id : owner_ids) {
            require(static_cast<size_t>(id) <= keygen.owner_keys.size(),
                    "Unknown real participant ID");
            selected.emplace_back(id, &keygen.owner_keys.at(id - 1));
        }
        started = Clock::now();
        auto signature = VirtualSign(keygen.registry, selected, argv[4]);
        const auto signing_seconds = std::chrono::duration<double>(Clock::now() - started);
        std::string r, s, public_x, public_y;
        signature.r.ToHexStr(r);
        signature.s.ToHexStr(s);
        keygen.registry.public_key.x().ToHexStr(public_x);
        keygen.registry.public_key.y().ToHexStr(public_y);
        std::cout << "signing_seconds=" << signing_seconds.count() << '\n'
                  << "real_signers=" << selected.size() << '\n'
                  << "virtual_signers=" << signature.virtual_signers << '\n'
                  << "public_x=" << public_x << '\n'
                  << "public_y=" << public_y << '\n'
                  << "signature_r=" << r << '\n'
                  << "signature_s=" << s << '\n'
                  << "recovery_id=" << signature.recovery_id << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Virtual GG18 error: " << error.what() << '\n';
        return 1;
    }
}
