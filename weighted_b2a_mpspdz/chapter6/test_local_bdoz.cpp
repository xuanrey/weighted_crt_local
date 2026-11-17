// Integration test of Python role files through the unchanged C++ VSC loader.
#include "../chapter4.hpp"
#include "../chapter5/protocol.hpp"
void require(bool ok,const char* message){if(!ok)throw runtime_error(message);}
int main(int argc, char** argv) { try {
    require(argc==5,"Usage: test_random_material directory weights T t");
    auto p=generate_weighted_parameters(parse_list(argv[2]),stoi(argv[3]),stoi(argv[4]),256);
    vector<int> degrees; int total=0;
    for(auto& party:p.parties){degrees.push_back(party.weight);total+=party.weight;}
    ch5::Scalar q("115792089237316195423570985008687907852837564279074904382605163141518161494337");
    auto pre=ch5::load_preprocessing(argv[1],degrees,total-p.reconstruction_threshold,p.m0.degree(),q,"test");
    for(size_t i=0;i<degrees.size();i++){
        ch5::verify(pre.input_masks[i],i,pre);ch5::verify(pre.zero.binary[i],i,pre);ch5::verify(pre.b2a.binary[i],i,pre);
    }
    bool failed=false;try{ch5::load_preprocessing(argv[1],degrees,total-p.reconstruction_threshold,p.m0.degree(),q,"test");}catch(const exception&){failed=true;}
    require(failed,"Consumed material accepted");
    auto secret=Polynomial(random_bits(p.m0.degree()));
    auto f=secret.add(Polynomial(random_bits(p.privacy_threshold)).mul(p.m0));
    vector<PartyShare> shares;for(auto& party:p.parties)shares.push_back({party.id,f.mod_poly(party.modulus)});
    auto s8=ch5::figure8::setup(shares,p,pre);
    auto bad=s8.shares[0];bad.value[0]^=1;failed=false;try{ch5::verify(bad,0,pre);}catch(const exception&){failed=true;}
    require(failed,"Tampered share accepted");
    auto u=ch5::figure8::convert(s8,pre);auto s9=ch5::figure9::setup(u,pre);auto out=ch5::figure9::convert(s9,pre);
    ch5::Scalar value=0,mac=0,alpha=0,expected=0;
    for(size_t i=0;i<degrees.size();i++){value+=out.x[i];mac+=out.mu[i];alpha+=pre.alpha[i];}
    for(int k=secret.degree();k>=0;k--)expected=ch5::mod(2*expected+secret.coeffs[k],q);
    require(ch5::mod(value,q)==expected,"Wrong VSC output");
    require(ch5::mod(mac-alpha*value,q)==0,"Wrong arithmetic MAC");
    cout<<"PASS: role loading, binary MACs, VSC output, arithmetic MAC, tamper/reuse rejection\n";
    return 0;
} catch(const exception& e){cerr<<e.what()<<endl;return 1;} }
