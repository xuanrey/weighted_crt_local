// Single-process Chapter 6 simulator. Private states share one address space.
#include "../chapter4.hpp"
#include "../chapter5/protocol.hpp"
#define main unused_virtual_benchmark_main
#include "../gg18/virtual_bench.cpp"
#undef main
#include "crypto-suites/crypto-sss/polynomial.h"
namespace fs = std::filesystem;
using ch5::Scalar;
const Scalar ORDER("115792089237316195423570985008687907852837564279074904382605163141518161494337");
Polynomial read_polynomial(istream& f) {
    string s; f >> s;
    require(bool(f) && s.size() >= 3 && s.front()=='[' && s.back()==']', "Invalid polynomial");
    return Polynomial(parse_list(s.substr(1,s.size()-2)));
}
Parameters read_parameters(const fs::path& file, string& sid) {
    ifstream f(file); Parameters p; int n;
    f >> sid >> p.scale >> p.reconstruction_threshold >> p.privacy_threshold >> n;
    require(bool(f) && n>=2, "Invalid parameters"); p.field_modulus=2;
    p.m0=read_polynomial(f);
    for(int i=0;i<n;i++){auto m=read_polynomial(f); p.parties.push_back({i,m.degree(),m});}
    require(p.m0.degree()>=256 && p.m0.degree()<=p.reconstruction_threshold-p.privacy_threshold,"Invalid secret width");
    long long total=0;
    for(auto& party:p.parties){require(party.weight<p.privacy_threshold,"Require max weight < t");total+=party.weight;}
    require(total>=p.reconstruction_threshold+p.privacy_threshold,"DKG weight below T+t");
    return p;
}
BN bn(const Scalar& s){return BN(s.get_str().c_str(),10);}
// Commit every point before opening any point. Includes session, purpose, owner and salt.
vector<CurvePoint> commit_open(const vector<CurvePoint>& points,const string& sid,const string& purpose) {
    vector<array<unsigned char,32>> salts(points.size()), hashes(points.size());
    auto hash=[&](size_t i){string x,y; points[i].x().ToHexStr(x);points[i].y().ToHexStr(y);
        string enc=sid+"|"+purpose+"|"+to_string(i)+"|"+(points[i].IsInfinity()?"O":x+":"+y)+"|";
        enc.append(reinterpret_cast<const char*>(salts[i].data()),32);
        array<unsigned char,32> h{};SHA256((const unsigned char*)enc.data(),enc.size(),h.data());return h;};
    for(size_t i=0;i<points.size();i++){require(RAND_bytes(salts[i].data(),32)==1,"RNG failed");hashes[i]=hash(i);}
    for(size_t i=0;i<points.size();i++)require(hashes[i]==hash(i),"Point commitment failed");
    return points;
}
CurvePoint sum_points(const vector<CurvePoint>& v){auto s=v.at(0);for(size_t i=1;i<v.size();i++)s+=v[i];return s;}
CurvePoint check_public(const ch5::figure9::Output& o,const ch5::Preprocessing& pre,const CurvePoint* expected=nullptr){
    auto curve=safeheron::curve::GetCurveParam(CurveType::SECP256K1);
    vector<CurvePoint> points;
    for(auto& x:o.x)points.push_back(curve->g*bn(x));
    auto Y=sum_points(commit_open(points,pre.sid,"Y"));
    require(!Y.IsInfinity(),"Zero public key");
    if(expected)require(Y==*expected,"Signing key differs from DKG key");
    points.clear();for(size_t i=0;i<o.mu.size();i++)points.push_back(curve->g*bn(o.mu[i])-Y*bn(pre.alpha[i]));
    require(sum_points(commit_open(points,pre.sid,"MAC")).IsInfinity(),"Figure 10 MAC failure");
    return Y;
}
// Retained solely for explicit debugging. Never called by DKG, signing or default tests.
void test_reconstruction(const vector<ch5::AuthBits>& u,const ch5::figure9::Output& o,
                         const ch5::Preprocessing& pre,const Polynomial& expected){
    double seconds;ch5::figure8::test_reconstruction(u,pre,expected,seconds);
    ch5::figure9::test_reconstruction(o,pre,expected,seconds);
}
// Trusted simulator adapter: change ONLY fresh preprocessing verification keys to
// the persistent Delta domain. Does not reauthenticate/change stored CRT shares.
// A distributed implementation needs a secure persistent-key preprocessing provider.
void rebase_preprocessing(ch5::Preprocessing& p,const vector<AuthElement>& delta){
    auto rebase=[&](vector<ch5::AuthBits>& values){for(size_t i=0;i<values.size();i++)
        for(size_t j=0;j<delta.size();j++)if(i!=j)
            for(size_t k=0;k<values[i].value.size();k++)if(values[i].value[k])
                values[i].key[j][k]=ch5::ax(values[i].key[j][k],ch5::ax(p.delta[j],delta[j]));};
    rebase(p.input_masks);rebase(p.zero.binary);rebase(p.b2a.binary);p.delta=delta;
}
vector<ch5::AuthBits> select_auth(const vector<ch5::AuthBits>& all,const vector<int>& ids){
    vector<ch5::AuthBits> selected;
    for(int id:ids){ch5::AuthBits a;a.value=all.at(id).value;
        for(int j:ids){a.tag.push_back(all.at(id).tag.at(j));a.key.push_back(all.at(id).key.at(j));}selected.push_back(a);}
    return selected;
}
ch5::figure8::State setup_bound(const Parameters& p,const vector<int>& ids,
                               const vector<ch5::AuthBits>& bound,ch5::Preprocessing& pre){
    ch5::figure8::State s;s.params=p;s.shares=bound;s.M=Polynomial({1});
    for(int id:ids)s.M=s.M.mul(p.parties.at(id).modulus);
    require(s.M.degree()>=p.reconstruction_threshold,"Signing weight below T");
    for(size_t i=0;i<ids.size();i++){
        ch5::verify(bound[i],i,pre);
        auto& mi=p.parties.at(ids[i]).modulus;auto q=s.M.div_rem(mi).first;
        s.lambda.push_back(q.mul(q.inverse_mod(mi)));}
    s.zero=ch5::generate_zero(pre);return s;
}
vector<gg::SignKey> adapt_additive(const KeygenResult& auxiliary,const vector<int>& ids,
                                const ch5::figure9::Output& o,const CurvePoint& Y,const string& sid){
    auto curve=safeheron::curve::GetCurveParam(CurveType::SECP256K1);
    vector<BN> indexes,lambda;for(int id:ids)indexes.push_back(BN(id+1));
    safeheron::sss::Polynomial::GetLArray(lambda,BN::ZERO,indexes,curve->n);
    vector<BN> adapted;vector<CurvePoint> pubs;
    for(size_t i=0;i<ids.size();i++){
        Scalar l;string decimal;lambda[i].ToDecStr(decimal);l=Scalar(decimal);
        Scalar inv;require(mpz_invert(inv.get_mpz_t(),l.get_mpz_t(),ORDER.get_mpz_t())!=0,"Zero Lagrange coefficient");
        adapted.push_back(bn(ch5::mod(o.x[i]*inv,ORDER)));pubs.push_back(curve->g*adapted.back());}
    vector<gg::SignKey> keys;
    for(size_t i=0;i<ids.size();i++){
        auto key=auxiliary.owner_keys.at(ids[i]).at(0);auto remotes=key.remote_parties_;
        key.workspace_id_=sid;key.threshold_=ids.size();key.n_parties_=ids.size();key.X_=Y;
        key.local_party_.index_=indexes[i];key.local_party_.x_=adapted[i];key.local_party_.g_x_=pubs[i];
        key.remote_parties_.clear();
        for(size_t j=0;j<ids.size();j++)if(j!=i){
            auto name=auxiliary.owner_keys.at(ids[j]).at(0).local_party_.party_id_;
            auto it=find_if(remotes.begin(),remotes.end(),[&](const auto& r){return r.party_id_==name;});
            require(it!=remotes.end(),"Missing auxiliary peer");auto r=*it;r.index_=indexes[j];r.g_x_=pubs[j];key.remote_parties_.push_back(r);}
        require(key.ValidityTest(),"Invalid additive adapter");keys.push_back(key);}
    return keys;
}
void sign_and_verify(const vector<gg::SignKey>& keys,const string& message,const fs::path& output){
    array<unsigned char,32> hash{};SHA256((const unsigned char*)message.data(),message.size(),hash.data());
    BN digest(hex(hash.data(),hash.size()).c_str(),16);
    vector<unique_ptr<gg::sign::Context>> owned;Contexts contexts;
    for(auto& key:keys){string encoded;require(key.ToBase64(encoded),"Key encoding failed");
        auto c=make_unique<gg::sign::Context>(keys.size());require(gg::sign::Context::CreateContext(*c,encoded,digest),"Sign context failed");
        contexts[key.local_party_.party_id_]=c.get();owned.push_back(move(c));}
    run_rounds(contexts);
    for(auto& c:owned){require(c->r_==owned[0]->r_ && c->s_==owned[0]->s_,"Signature disagreement");
        require(safeheron::curve::ecdsa::VerifyPublicKey(keys[0].X_,CurveType::SECP256K1,digest,c->r_,c->s_,c->v_),"ECDSA verification failed");}
    string r,s,x,y;owned[0]->r_.ToHexStr(r);owned[0]->s_.ToHexStr(s);keys[0].X_.x().ToHexStr(x);keys[0].X_.y().ToHexStr(y);
    ofstream f(output);f<<"{\"digest\":\""<<hex(hash.data(),32)<<"\",\"r\":\""<<r<<"\",\"s\":\""<<s<<"\",\"public_x\":\""<<x<<"\",\"public_y\":\""<<y<<"\",\"verified\":true}\n";
}
#ifndef CH6_NO_MAIN
int main(int argc,char** argv){umask(0077);try{
    require(argc==2,"Usage: chapter6 session_directory");fs::path root=argv[1];
    string sid;auto p=read_parameters(root/"dealer-0/parameters.txt",sid);int n=p.parties.size();
    vector<vector<Polynomial>> dealer(n);double vss=0;
    for(int j=0;j<n;j++){
        string ds;auto dp=read_parameters(root/("dealer-"+to_string(j))/"parameters.txt",ds);
        require(dp.m0.coeffs==p.m0.coeffs,"Dealer m0 mismatch");
        for(int i=0;i<n;i++)require(dp.parties[i].modulus.coeffs==p.parties[i].modulus.coeffs,"Dealer modulus mismatch");
        ifstream f(root/("dealer-"+to_string(j))/"accepted_crt.txt");string saved;int count;f>>saved>>count;
        require(saved==ds && count==n,"Dealer acceptance mismatch");
        for(int i=0;i<n;i++){int id;f>>id;require(id==i,"Dealer party mismatch");dealer[j].push_back(read_polynomial(f));}
    }
    ifstream times(root/"vss_seconds.txt");times>>vss;require(bool(times),"Missing VSS time");
    auto start=Clock::now();vector<PartyShare> aggregate;vector<int> all,degrees;
    for(int i=0;i<n;i++){Polynomial a;for(int j=0;j<n;j++)a=a.add(dealer[j][i]);aggregate.push_back({i,a});all.push_back(i);degrees.push_back(p.parties[i].weight);}
    double extra=ch5::elapsed(start);int d=0;for(int v:degrees)d+=v;
    auto pre=ch5::load_preprocessing(root/"dkg/preprocessing",degrees,d-p.reconstruction_threshold,p.m0.degree(),ORDER,sid+"-dkg");
    start=Clock::now();auto s8=ch5::figure8::setup(aggregate,p,pre);auto retained=s8.shares;auto delta=pre.delta;double offline_setup=ch5::elapsed(start);
    double c8,c9;auto u=ch5::figure8::test_convert(s8,pre,c8);start=Clock::now();auto s9=ch5::figure9::setup(u,pre);offline_setup+=ch5::elapsed(start);auto out=ch5::figure9::test_convert(s9,pre,c9);
    start=Clock::now();auto Y=check_public(out,pre);extra+=ch5::elapsed(start);
    string px,py;Y.x().ToHexStr(px);Y.y().ToHexStr(py);ofstream(root/"public_key.txt")<<px<<"\n"<<py<<"\n";
    double offline_seconds=0;ifstream offline_file(root/"dkg/offline_seconds.txt");offline_file>>offline_seconds;require(bool(offline_file),"Missing offline timer");
    // One-time GG18 auxiliary setup (Paillier keys, range proofs). This is offline
    // material shared by all signing sessions: it is NOT part of the PolyCRT DKG,
    // so it is reported in its own column rather than inside DKG_total.
    cout<<"Preparing reusable GG18 auxiliary material (offline)..."<<endl;
    auto aux_start=Clock::now();
    auto auxiliary=VirtualKeyGen(vector<int>(n,1),n);
    double aux_offline=ch5::elapsed(aux_start);
    for(auto& owner:auxiliary.owner_keys)owner[0].local_party_.x_=BN::ZERO;
    ofstream results(root/"results.csv");results<<"stage,name,VSS,VSC_offline,VSC_online,Figure10_extra,DKG_total,GG18_aux_offline,sign_total,status\n"<<setprecision(17);
    results<<"dkg,dkg,"<<vss<<","<<offline_seconds+offline_setup<<","<<c8+c9<<","<<extra<<","<<vss+c8+c9+extra<<","<<aux_offline<<",,passed\n";results.flush();
    cout<<fixed<<setprecision(9)<<"VSS: "<<vss<<" s\nVSC offline: "<<offline_seconds+offline_setup<<" s\nVSC online: "<<c8+c9<<" s\nFigure 10 additional: "<<extra<<" s\nDKG total: "<<vss+c8+c9+extra<<" s\nGG18 auxiliary (offline): "<<aux_offline<<" s\nOffline total: "<<offline_seconds+offline_setup+aux_offline<<" s"<<endl;
    ifstream plan(root/"sign_plan.txt");string name,ids_csv,message;
    while(plan>>name>>ids_csv>>message){
        auto ids=parse_list(ids_csv);set<int> seen;int weight=0;
        for(int id:ids){require(id>=0 && id<n && seen.insert(id).second,"Invalid signing IDs");weight+=p.parties[id].weight;}
        if(weight<p.reconstruction_threshold || ids.size()<2){cout<<name<<": expected unauthorized-set rejection"<<endl;results<<"sign,"<<name<<",,,,,,,,rejected\n";continue;}
        vector<int> deg;vector<AuthElement> sd;for(int id:ids){deg.push_back(p.parties[id].weight);sd.push_back(delta[id]);}
        auto sp=ch5::load_preprocessing(root/name/"preprocessing",deg,weight-p.reconstruction_threshold,p.m0.degree(),ORDER,sid+"-"+name);
        rebase_preprocessing(sp,sd);auto bound=select_auth(retained,ids);
        // Negative tests verify binding before any masked output is opened.
        auto bad=bound;bad[0].value[0]^=1;bool rejected=false;try{ch5::verify(bad[0],0,sp);}catch(const exception&){rejected=true;}require(rejected,"Tampered CRT share accepted");
        auto state=setup_bound(p,ids,bound,sp);
        start=Clock::now();auto bu=ch5::figure8::convert(state,sp);auto bs=ch5::figure9::setup(bu,sp);auto bo=ch5::figure9::convert(bs,sp);
        check_public(bo,sp,&Y);
        auto keys=adapt_additive(auxiliary,ids,bo,Y,sp.sid);sign_and_verify(keys,message,root/name/"signature.json");
        double seconds=ch5::elapsed(start);results<<"sign,"<<name<<",,,,,,,"<<seconds<<",passed\n";results.flush();cout<<name<<" sign: "<<seconds<<" s; verified against DKG public key"<<endl;
    }
    return 0;
}catch(const exception& e){cerr<<"Chapter 6 failed: "<<e.what()<<endl;return 1;}}

#endif
