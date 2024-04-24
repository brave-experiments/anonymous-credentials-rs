use brave_miracl::{
    bn254::{
        big::{self, BIG},
        ecp::ECP,
        ecp2::ECP2,
        fp12::FP12,
        pair::g1mul,
    },
    rand::RAND,
};

use super::util::{
    ecp_challenge_equals, hash256, pair_normalized_triple_ate, random_mod_curve_order,
    CURVE_ORDER_BIG, G1_ECP, G2_ECP,
};
use super::Result;
use super::{
    data::{
        CredentialBIG, ECPProof, GroupPublicKey, JoinRequest, JoinResponse, StartJoinResult,
        UserCredentials, ECP_SIZE,
    },
    CredentialError,
};

fn ecp_challenge(message: &[u8; big::MODBYTES], y: &ECP, g: &ECP, gr: &ECP) -> BIG {
    let mut all_bytes = [0u8; ECP_SIZE * 3 + big::MODBYTES];

    all_bytes[..big::MODBYTES].copy_from_slice(message);

    y.tobytes(&mut all_bytes[big::MODBYTES..], false);
    g.tobytes(&mut all_bytes[ECP_SIZE + big::MODBYTES..], false);
    gr.tobytes(&mut all_bytes[ECP_SIZE * 2 + big::MODBYTES..], false);

    let hash = hash256(&all_bytes);

    let mut c = BIG::frombytes(&hash);
    c.rmod(&CURVE_ORDER_BIG);
    c
}

fn make_ecp_proof(rng: &mut RAND, y: &ECP, x: &BIG, message: &[u8; big::MODBYTES]) -> ECPProof {
    let r = random_mod_curve_order(rng);

    let g = G1_ECP.clone();
    let gr = g1mul(&g, &r);
    let c = ecp_challenge(message, y, &g, &gr);
    let mut s = BIG::modmul(&c, x, &CURVE_ORDER_BIG);
    s.add(&r);
    s.rmod(&CURVE_ORDER_BIG);
    ECPProof { c, s }
}

fn verify_ecp_proof_equals(a: &ECP, b: &ECP, y: &ECP, z: &ECP, proof: &ECPProof) -> bool {
    let cn = BIG::modneg(&proof.c, &CURVE_ORDER_BIG);

    let mut r#as = g1mul(a, &proof.s);
    let yc = g1mul(y, &cn);
    let mut bs = g1mul(b, &proof.s);
    let zc = g1mul(z, &cn);

    r#as.add(&yc);
    bs.add(&zc);

    let cc = ecp_challenge_equals(None, &y, &z, &a, &b, &r#as, &bs);

    BIG::comp(&proof.c, &cc) == 0
}

fn verify_aux_fast(a: &ECP, b: &ECP, c: &ECP, d: &ECP, x: &ECP2, y: &ECP2, rng: &mut RAND) -> bool {
    if a.is_infinity() {
        return false;
    }

    let e1 = random_mod_curve_order(rng);
    let e2 = random_mod_curve_order(rng);
    let ne1 = BIG::modneg(&e1, &CURVE_ORDER_BIG);
    let ne2 = BIG::modneg(&e2, &CURVE_ORDER_BIG);

    // AA = e1 * A
    let aa = g1mul(a, &e1);

    // BB = -e1 * B
    let mut bb = g1mul(b, &ne1);

    // CC = -e2 * C
    let mut cc = g1mul(c, &ne2);

    // BB = (-e1 * B) + (-e2 * C)
    bb.add(&cc);

    // CC = e2 * (A + D)
    cc.copy(a);
    cc.add(d);
    cc = g1mul(&cc, &e2);

    // w = e(e1·A, Y)·e((-e1·B) + (-e2·C), G2)·e(e2·(A + D), X)
    let w = pair_normalized_triple_ate(y, &aa, &G2_ECP, &bb, x, &cc);

    let mut fp12_one = FP12::new();
    fp12_one.one();

    w.equals(&fp12_one)
}

pub fn start_join(rng: &mut RAND, challenge: &[u8]) -> StartJoinResult {
    let gsk = random_mod_curve_order(rng);
    let q = g1mul(&G1_ECP, &gsk);

    let challenge_hash = hash256(challenge);

    let proof = make_ecp_proof(rng, &q, &gsk, &challenge_hash);

    StartJoinResult {
        gsk: CredentialBIG(gsk),
        join_msg: JoinRequest { q, proof },
    }
}

pub fn finish_join(
    pub_key: &GroupPublicKey,
    gsk: &CredentialBIG,
    resp: JoinResponse,
) -> Result<UserCredentials> {
    let q = g1mul(&G1_ECP, &gsk.0);

    let mut rng = RAND::new();
    rng.seed(big::MODBYTES, &gsk.to_bytes());

    if !verify_ecp_proof_equals(&G1_ECP, &q, &resp.cred.b, &resp.cred.d, &resp.proof) {
        return Err(CredentialError::JoinResponseValidation);
    }

    if !verify_aux_fast(
        &resp.cred.a,
        &resp.cred.b,
        &resp.cred.c,
        &resp.cred.d,
        &pub_key.x,
        &pub_key.y,
        &mut rng,
    ) {
        return Err(CredentialError::JoinResponseValidation);
    }

    Ok(resp.cred)
}