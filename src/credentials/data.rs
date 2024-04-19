use brave_miracl::bn254::{
    big::{self, BIG},
    ecp::ECP,
    ecp2::ECP2,
    fp2::FP2,
};

use super::CredentialError;

pub const ECP_BYTES_SIZE: usize = big::MODBYTES * 2 + 1;
pub const ECP2_COMPAT_BYTES_SIZE: usize = big::MODBYTES * 4;

pub const JOIN_REQUEST_SIZE: usize = ECP_BYTES_SIZE + (big::MODBYTES * 2);
pub const USER_CREDENTIALS_SIZE: usize = ECP_BYTES_SIZE * 4;
pub const JOIN_RESPONSE_SIZE: usize = USER_CREDENTIALS_SIZE + (big::MODBYTES * 2);
pub const GROUP_PUBLIC_KEY_SIZE: usize = (ECP2_COMPAT_BYTES_SIZE * 2) + (big::MODBYTES * 4);

pub struct JoinRequest {
    pub q: ECP, // G1 ** gsk

    pub c: BIG,
    pub s: BIG,
}

pub struct JoinResponse {
    pub cred: UserCredentials,
    pub c: BIG,
    pub s: BIG,
}

pub struct UserCredentials {
    pub a: ECP,
    pub b: ECP,
    pub c: ECP,
    pub d: ECP,
}

pub struct GroupPublicKey {
    pub x: ECP2, // G2 ** x
    pub y: ECP2, // G2 ** y

    // ZK of discrete-log knowledge for X and Y
    pub cx: BIG,
    pub sx: BIG,
    pub cy: BIG,
    pub sy: BIG,
}

pub struct ECPProof {
    pub c: BIG,
    pub s: BIG,
}

pub struct CredentialBIG(pub BIG);

pub struct StartJoinResult {
    pub gsk: CredentialBIG,
    pub join_msg: JoinRequest,
}

pub fn ecp_from_bytes(bytes: &[u8]) -> Result<ECP, CredentialError> {
    if bytes.len() != ECP_BYTES_SIZE {
        return Err(CredentialError::BadECP);
    }
    Ok(ECP::frombytes(bytes))
}

pub fn ecp2_from_compat_bytes(bytes: &[u8]) -> Result<ECP2, CredentialError> {
    if bytes.len() != ECP2_COMPAT_BYTES_SIZE {
        return Err(CredentialError::BadECP2);
    }
    let x = FP2::new_bigs(
        &big_from_bytes(&bytes[..big::MODBYTES])?,
        &big_from_bytes(&bytes[big::MODBYTES..big::MODBYTES * 2])?,
    );
    let y = FP2::new_bigs(
        &big_from_bytes(&bytes[big::MODBYTES * 2..big::MODBYTES * 3])?,
        &big_from_bytes(&bytes[big::MODBYTES * 3..big::MODBYTES * 4])?,
    );
    Ok(ECP2::new_fp2s(&x, &y))
}

pub fn big_from_bytes(bytes: &[u8]) -> Result<BIG, CredentialError> {
    if bytes.len() != big::MODBYTES {
        return Err(CredentialError::BadBIG);
    }
    Ok(BIG::frombytes(bytes))
}

impl TryFrom<&[u8]> for JoinResponse {
    type Error = CredentialError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != JOIN_RESPONSE_SIZE {
            return Err(CredentialError::BadJoinResponse);
        }

        Ok(JoinResponse {
            cred: bytes[..USER_CREDENTIALS_SIZE].try_into()?,
            c: big_from_bytes(
                &bytes[USER_CREDENTIALS_SIZE..big::MODBYTES + USER_CREDENTIALS_SIZE],
            )?,
            s: big_from_bytes(&bytes[USER_CREDENTIALS_SIZE + big::MODBYTES..])?,
        })
    }
}

impl TryFrom<&[u8]> for UserCredentials {
    type Error = CredentialError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != USER_CREDENTIALS_SIZE {
            return Err(CredentialError::BadUserCredentials);
        }
        Ok(UserCredentials {
            a: ecp_from_bytes(&bytes[..ECP_BYTES_SIZE])?,
            b: ecp_from_bytes(&bytes[ECP_BYTES_SIZE..ECP_BYTES_SIZE * 2])?,
            c: ecp_from_bytes(&bytes[ECP_BYTES_SIZE * 2..ECP_BYTES_SIZE * 3])?,
            d: ecp_from_bytes(&bytes[ECP_BYTES_SIZE * 3..ECP_BYTES_SIZE * 4])?,
        })
    }
}

impl TryFrom<&[u8]> for GroupPublicKey {
    type Error = CredentialError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != GROUP_PUBLIC_KEY_SIZE {
            return Err(CredentialError::GroupPublicKeyLength);
        }

        let big_start = ECP2_COMPAT_BYTES_SIZE * 2;

        Ok(GroupPublicKey {
            x: ecp2_from_compat_bytes(&bytes[..ECP2_COMPAT_BYTES_SIZE])?,
            y: ecp2_from_compat_bytes(&bytes[ECP2_COMPAT_BYTES_SIZE..ECP2_COMPAT_BYTES_SIZE * 2])?,
            cx: big_from_bytes(&bytes[big_start..big_start + big::MODBYTES])?,
            sx: big_from_bytes(&bytes[big_start + big::MODBYTES..big_start + big::MODBYTES * 2])?,
            cy: big_from_bytes(
                &bytes[big_start + big::MODBYTES * 2..big_start + big::MODBYTES * 3],
            )?,
            sy: big_from_bytes(
                &bytes[big_start + big::MODBYTES * 3..big_start + big::MODBYTES * 4],
            )?,
        })
    }
}

impl CredentialBIG {
    pub fn to_bytes(&self) -> [u8; big::MODBYTES] {
        let mut bytes = [0u8; big::MODBYTES];
        self.0.tobytes(&mut bytes);
        bytes
    }
}

impl TryFrom<&[u8]> for CredentialBIG {
    type Error = CredentialError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(big_from_bytes(bytes)?))
    }
}

impl JoinRequest {
    pub fn to_bytes(&self) -> [u8; JOIN_REQUEST_SIZE] {
        let mut result = [0u8; JOIN_REQUEST_SIZE];
        self.q.tobytes(&mut result, false);
        self.c.tobytes(&mut result[ECP_BYTES_SIZE..]);
        self.s
            .tobytes(&mut result[ECP_BYTES_SIZE + big::MODBYTES..]);
        result
    }
}

impl UserCredentials {
    pub fn to_bytes(&self) -> [u8; USER_CREDENTIALS_SIZE] {
        let mut result = [0u8; USER_CREDENTIALS_SIZE];
        self.a.tobytes(&mut result[..ECP_BYTES_SIZE], false);
        self.b
            .tobytes(&mut result[ECP_BYTES_SIZE..ECP_BYTES_SIZE * 2], false);
        self.c
            .tobytes(&mut result[ECP_BYTES_SIZE * 2..ECP_BYTES_SIZE * 3], false);
        self.d
            .tobytes(&mut result[ECP_BYTES_SIZE * 3..ECP_BYTES_SIZE * 4], false);
        result
    }
}
