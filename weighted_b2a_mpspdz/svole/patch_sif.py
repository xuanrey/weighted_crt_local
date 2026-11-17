#!/usr/bin/env python3
"""Create a narrow, documented SIF overlay; keep the pinned checkout unchanged."""
from pathlib import Path
import sys

source, overlay = map(Path, sys.argv[1:])

def replace_once(text, old, new):
    if text.count(old) != 1:
        raise SystemExit('Unexpected upstream source; refusing to apply the SIF overlay')
    return text.replace(old, new)

helper = (source / 'third_party/emp-agmpc/emp-agmpc/helper.h').read_text()
# Public transcript echo: honest participants must see the same public value.
agreement = r'''
// Adapter addition: compare public transcript hashes over all peer connections.
// This is an echo check, not a general Byzantine reliable-broadcast service.
template<int nP>
void auth_agree(NetIOMP<nP>* io, int party, const void* value, int size) {
    unsigned char own[Hash::DIGEST_SIZE], received[Hash::DIGEST_SIZE];
    Hash::hash_once(own, value, size);
    for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
        io->send_data(peer, own, sizeof(own));
        io->flush(peer);
    }
    bool ok = true;
    for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
        io->recv_data(peer, received, sizeof(received));
        ok = (memcmp(own, received, sizeof(own)) == 0) && ok;
    }
    if (!ok) throw std::runtime_error("Inconsistent public sVOLE transcript");
}
'''
helper = replace_once(helper, 'template<int nP>\nblock sampleRandom', agreement + '\ntemplate<int nP>\nblock sampleRandom')
helper = replace_once(helper, 'cheat = cheat or v.get();', 'cheat = v.get() or cheat;')
helper = replace_once(helper, 'return strncmp(tmp, dgst[party2], Hash::DIGEST_SIZE)!=0;',
                      'return memcmp(tmp, dgst[party2], Hash::DIGEST_SIZE)!=0;')
helper = replace_once(helper, 'bool cheat = joinNcleanCheat(res2);',
                      'bool cheat = joinNcleanCheat(res2);\n\tauth_agree(io, party, dgst + 1, nP * Hash::DIGEST_SIZE);\n\tauth_agree(io, party, S + 1, nP * sizeof(block));')
helper = replace_once(helper, 'exit(0);', 'throw std::runtime_error("sVOLE coin opening check failed");')

vole = (source / 'mv-svole/mvsvole_bool_iknp.h').read_text()
vole = replace_once(vole, 'int ssp;', 'int ssp;\n    int retained_length = 0;')
vole = replace_once(vole, 'new IKNP<NetIO>(io->get(i, false));',
                     'new IKNP<NetIO>(io->get(i, false), true);')
vole = replace_once(vole, 'new IKNP<NetIO>(io->get(1, false));',
                     'new IKNP<NetIO>(io->get(1, false), true);')
# Flush the exact COT channel, including final active-check messages.
vole = replace_once(vole, 'abit[party2]->recv_cot(output[party2], data, length);',
                     'abit[party2]->recv_cot(output[party2], data, length);\n                    abit[party2]->io->flush();')
vole = replace_once(vole, 'abit[1]->send_cot(output[1], length);',
                     'abit[1]->send_cot(output[1], length);\n            abit[1]->io->flush();')
# Check that the discarded random suffix completely masks the public syndrome.
rank_check = r'''
        // Adapter addition: retain only the prefix; discard all auxiliary bits.
        // Full row rank of the suffix matrix makes the published syndrome
        // independent of the retained prefix for honest random preprocessing.
        if (retained_length <= 0 || length-retained_length < ssp)
            throw std::runtime_error("Insufficient auxiliary sVOLE correlations");
        int tail = length-retained_length;
        std::vector<std::vector<unsigned char>> matrix(ssp, std::vector<unsigned char>(tail));
        for (int row = 0; row < ssp; ++row)
            for (int col = 0; col < tail; ++col)
                matrix[row][col] = s[row*length+retained_length+col];
        int rank = 0;
        for (int col = 0; col < tail && rank < ssp; ++col) {
            int pivot = rank;
            while (pivot < ssp && !matrix[pivot][col]) ++pivot;
            if (pivot == ssp) continue;
            std::swap(matrix[rank], matrix[pivot]);
            for (int row = rank+1; row < ssp; ++row) if (matrix[row][col])
                for (int j = col; j < tail; ++j) matrix[row][j] ^= matrix[rank][j];
            ++rank;
        }
        if (rank != ssp) throw std::runtime_error("Rank-deficient sVOLE mask; discard this session");
'''
vole = replace_once(vole, 'prg2.random_bool(s, length*ssp);', 'prg2.random_bool(s, length*ssp);\n' + rank_check)
vole = replace_once(vole, 'cout << "Consistency checks for mv-svole fail" << endl;',
                     'throw std::runtime_error("Multi-verifier sVOLE consistency check failed");')
vole = replace_once(vole, '\n    }\n\n    /* debug function*/',
                     '\n        auth_agree(io, party, u, ssp*sizeof(bool));\n        delete[] s;\n        delete[] u;\n    }\n\n    /* debug function*/')
# The upstream verifier leaked these temporary arrays on each call.
vole = replace_once(vole, 'if (!flag)\n', 'delete[] tmpK;\n            delete[] tmpM;\n            if (!flag)\n')
for relative, content in [('emp-agmpc/netmp.h', (source/'third_party/emp-agmpc/emp-agmpc/netmp.h').read_text()), ('emp-agmpc/cmpc_config.h', (source/'third_party/emp-agmpc/emp-agmpc/cmpc_config.h').read_text()), ('emp-agmpc/helper.h', helper), ('mv-svole/mvsvole_bool_iknp.h', vole)]:
    path = overlay / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
