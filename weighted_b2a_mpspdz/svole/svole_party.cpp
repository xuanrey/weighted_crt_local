// Real SIF/EMP preprocessing only. This program does not simulate correlations.
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <emp-tool/emp-tool.h>
using namespace emp;
#include "mv-svole/mvsvole_bool_iknp.h"
#ifndef TOTAL_PARTIES
#define TOTAL_PARTIES 4
#endif
constexpr int NP = TOTAL_PARTIES; // Includes the dealer, numbered 1.

int main(int argc, char** argv) {
    umask(0077);
    try {
        if (argc != 6) throw std::runtime_error("Usage: svole_party party port T sid output_dir");
        int party = std::stoi(argv[1]), port = std::stoi(argv[2]), T = std::stoi(argv[3]);
        std::string sid = argv[4];
        if (party < 1 || party > NP || NP > 40 || T < 1 || T > 1000000)
            throw std::runtime_error("Invalid sVOLE parameters (at most 39 users)");
        // Forty checked equations plus forty extra random suffix bits.
        constexpr int SSP = 40;
        int length = T + 2*SSP;
        NetIOMP<NP> network(party, port);
        ThreadPool pool(2*NP+2);
        MVSVOLEBOOL_IKNP<NP> vole(&network, &pool, party, SSP);
        vole.retained_length = T;
        std::unique_ptr<bool[]> bits(new bool[length]);
        block* correlations[NP+1] = {};
        for (int i = 1; i <= NP; ++i) correlations[i] = new block[length];
        // The overlay enables malicious IKNP checks, full-rank masking,
        // consistent public transcript echoes, and fail-closed behavior.
        vole.computeVOLE_mal(correlations, bits.get(), length);
        network.sync();
        std::filesystem::path directory(argv[5]);
        std::filesystem::create_directories(directory);
        std::filesystem::path path = directory / (party == 1 ? "dealer.bin" :
            "party-P" + std::to_string(party-2) + ".bin");
        std::ofstream output(path, std::ios::binary);
        output << "AUTHV1 " << sid << " " << T << " " << NP-1 << "\n";
        // block is a 128-bit polynomial-basis bit string on this x86 backend.
        if (party == 1) {
            for (int j = 0; j < T; ++j) output.put(bits[j] ? 1 : 0);
            for (int user = 2; user <= NP; ++user)
                output.write(reinterpret_cast<char*>(correlations[user]), T*sizeof(block));
        } else {
            output.write(reinterpret_cast<char*>(&vole.Delta), sizeof(block));
            output.write(reinterpret_cast<char*>(correlations[1]), T*sizeof(block));
        }
        output.close();
        if (!output) throw std::runtime_error("Cannot write private authentication material");
        for (int i = 1; i <= NP; ++i) delete[] correlations[i];
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "sVOLE error: " << error.what() << "\n";
        return 1;
    }
}
