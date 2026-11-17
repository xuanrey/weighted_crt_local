# Safeheron dependency notice

This integration uses multi-party-sig-cpp, copyright Safeheron Inc. 2023, and
safeheron-crypto-suites-cpp, copyright Safeheron Inc. 2022. These programs are
licensed for Non-Commercial Use under their respective upstream license terms.
The GG18 resulting combination and its distribution retain the same notice
requirement and Non-Commercial Use restriction. Consult the complete license
texts bundled alongside this notice:

- [multi-party-sig-cpp license](LICENSE.Safeheron.MultiPartySig)
- [safeheron-crypto-suites-cpp license](LICENSE.Safeheron.CryptoSuites)

The libraries are downloaded locally by setup_gg18.sh rather than vendored into
this archive. The adapter is an independent research integration and is neither
endorsed by Safeheron nor covered by its upstream audit.

Protobuf v3.20.3 is built locally from its upstream repository and retains its
own upstream license. MP-SPDZ is installed separately and retains its own
upstream license. No additional blanket license for the author's original
research code is selected by this package.
