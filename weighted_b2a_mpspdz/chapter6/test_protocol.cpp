// Explicit ideal-correlation unit test. NOT the real preprocessing benchmark.
#define CH6_NO_MAIN
#include "main.cpp"
Scalar random_scalar(){unsigned char bytes[32];require(RAND_bytes(bytes,32)==1,"RNG");Scalar s;mpz_import(s.get_mpz_t(),32,1,1,0,0,bytes);return ch5::mod(s,ORDER);}
ch5::AuthBits authenticate(vector<int> value,int owner,const vector<AuthElement>& delta){
    ch5::AuthBits a;a.value=value;a.tag.resize(delta.size());a.key.resize(delta.size());
    for(size_t j=0;j<delta.size();j++)if(int(j)!=owner)for(int b:value){AuthElement tag{};require(RAND_bytes(tag.data(),16)==1,"RNG");a.tag[j].push_back(tag);a.key[j].push_back(b?ch5::ax(tag,delta[j]):tag);}return a;
}
ch5::Preprocessing ideal(const vector<int>& degrees,int h,int d0,string sid){
    ch5::Preprocessing p;p.q=ORDER;p.sid=sid;int n=degrees.size();p.delta.resize(n);Scalar alpha=0;
    for(int i=0;i<n;i++){require(RAND_bytes(p.delta[i].data(),16)==1,"RNG");p.alpha.push_back(random_scalar());alpha=ch5::mod(alpha+p.alpha.back(),ORDER);p.input_masks.push_back(ch5::AuthBits());}
    for(int i=0;i<n;i++)p.input_masks[i]=authenticate(random_bits(degrees[i]),i,p.delta);
    auto make=[&](int length){ch5::DaBits d;d.a.resize(n);d.g.resize(n);
        for(int i=0;i<n;i++)d.binary.push_back(authenticate(random_bits(length),i,p.delta));
        for(int k=0;k<length;k++){int b=0;for(int i=0;i<n;i++)b^=d.binary[i].value[k];Scalar a=0,g=0;
            for(int i=0;i<n-1;i++){d.a[i].push_back(random_scalar());d.g[i].push_back(random_scalar());a+=d.a[i].back();g+=d.g[i].back();}
            d.a[n-1].push_back(ch5::mod(b-a,ORDER));d.g[n-1].push_back(ch5::mod(alpha*b-g,ORDER));}return d;};
    p.zero=make(h);p.b2a=make(d0);return p;
}
int main(){try{
    auto p=generate_weighted_parameters({2,2,2,2},5,3,256);int n=4;vector<Polynomial> agg(n);
    for(int dealer=0;dealer<n;dealer++){auto f=Polynomial(random_bits(256)).add(Polynomial(random_bits(p.privacy_threshold)).mul(p.m0));
        for(int i=0;i<n;i++)agg[i]=agg[i].add(f.mod_poly(p.parties[i].modulus));}
    vector<PartyShare> shares;vector<int> degree;for(int i=0;i<n;i++){shares.push_back({i,agg[i]});degree.push_back(p.parties[i].weight);}
    auto pre=ideal(degree,1024-640,256,"unit-dkg");auto s=ch5::figure8::setup(shares,p,pre);auto retained=s.shares;
    auto u=ch5::figure8::convert(s,pre);auto s9=ch5::figure9::setup(u,pre);auto o=ch5::figure9::convert(s9,pre);auto Y=check_public(o,pre);
    auto corrupt=o;corrupt.mu[0]=ch5::mod(corrupt.mu[0]+1,ORDER);bool failed=false;
    try{check_public(corrupt,pre);}catch(const exception&){failed=true;}require(failed,"Bad group MAC accepted");
    cout<<"VSC + Figure 10 + bad group MAC: PASS"<<endl;
    auto auxiliary=VirtualKeyGen(vector<int>(4,1),4);
    vector<vector<int>> sets={{0,1,2},{1,2,3},{0,1,2}};
    for(size_t k=0;k<sets.size();k++){auto ids=sets[k];auto sp=ideal({256,256,256},128,256,"unit-sign-"+to_string(k));
        vector<AuthElement> delta;for(int id:ids)delta.push_back(pre.delta[id]);rebase_preprocessing(sp,delta);
        auto bound=select_auth(retained,ids);auto bad=bound;bad[0].value[0]^=1;failed=false;
        try{ch5::verify(bad[0],0,sp);}catch(const exception&){failed=true;}require(failed,"Tamper accepted");
        auto st=setup_bound(p,ids,bound,sp);auto v=ch5::figure8::convert(st,sp);auto t=ch5::figure9::setup(v,sp);auto out=ch5::figure9::convert(t,sp);check_public(out,sp,&Y);
        auto keys=adapt_additive(auxiliary,ids,out,Y,sp.sid);sign_and_verify(keys,"unit-message-"+to_string(k),fs::temp_directory_path()/("ch6-unit-sign-"+to_string(k)+".json"));
        failed=false;try{ch5::figure8::convert(st,sp);}catch(const exception&){failed=true;}require(failed,"Conversion reuse accepted");
        cout<<"sign "<<k+1<<": PASS (same DKG key, fresh session, tamper/reuse rejection)"<<endl;
    }
    auto sp=ideal({256,256},0,256,"unauthorized");auto b=select_auth(retained,{0,1});failed=false;
    try{setup_bound(p,{0,1},b,sp);}catch(const exception&){failed=true;}require(failed,"Unauthorized accepted");
    cout<<"Unauthorized set: PASS\nReconstruction calls: NONE\n";return 0;
}catch(const exception& e){cerr<<e.what()<<endl;return 1;}}
