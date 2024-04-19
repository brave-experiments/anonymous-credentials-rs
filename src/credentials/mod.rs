mod data;
mod join;
mod util;

use brave_miracl::{bn254::big, rand::RAND};
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;

use self::data::{
    CredentialBIG, GroupPublicKey, JoinResponse, StartJoinResult, UserCredentials,
    ECP2_COMPAT_BYTES_SIZE, ECP_BYTES_SIZE, GROUP_PUBLIC_KEY_SIZE, JOIN_RESPONSE_SIZE,
    USER_CREDENTIALS_SIZE,
};
use self::join::{join_client_internal, join_finish_client_internal};

#[derive(Error, Debug)]
pub enum CredentialError {
    #[error("ECP should be {0} bytes", ECP_BYTES_SIZE)]
    BadECP,
    #[error("ECP2 should be {0} bytes", ECP2_COMPAT_BYTES_SIZE)]
    BadECP2,
    #[error("BIG should be {0} bytes", big::MODBYTES)]
    BadBIG,
    #[error("User credentials should be {0} bytes", USER_CREDENTIALS_SIZE)]
    BadUserCredentials,
    #[error("Join response should be {0} bytes", JOIN_RESPONSE_SIZE)]
    BadJoinResponse,
    #[error("Group public key should be {0} bytes", GROUP_PUBLIC_KEY_SIZE)]
    GroupPublicKeyLength,
    #[error("Join response validation failed")]
    JoinResponseValidation,
}

pub type Result<T> = std::result::Result<T, CredentialError>;

pub struct CredentialManager {
    rng: RAND,
}

impl CredentialManager {
    pub fn new() -> Self {
        let mut entropy = [0u8; 128];
        OsRng::default().fill_bytes(&mut entropy);
        Self::new_with_seed(&entropy)
    }

    fn new_with_seed(entropy: &[u8]) -> Self {
        let mut rng = RAND::new();

        rng.seed(entropy.len(), entropy);

        Self { rng }
    }

    pub fn start_join(&mut self, challenge: &[u8]) -> StartJoinResult {
        join_client_internal(&mut self.rng, challenge)
    }

    pub fn finish_join(
        &mut self,
        public_key: &GroupPublicKey,
        gsk: &CredentialBIG,
        join_resp: JoinResponse,
    ) -> Result<UserCredentials> {
        join_finish_client_internal(public_key, gsk, join_resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;

    lazy_static! {
        static ref EXPECTED_GSK: Vec<u8> =
            hex::decode("0198c86f99ede0ca2ed30b8e4ae6cac831c9b398445422a41d95abb4d3f03499")
                .unwrap();
        static ref GROUP_PUB_KEY: Vec<u8> = hex::decode(
            "0477ce930400ab04a6e1caa46601dbd1b1ba5d24f0577834a960285a0512e7ed\
            0174121707ea5d80e083d2e992236864608998a4d08cb3a41dde1fc6b7eaad5b2\
            125310b44ca712bf63f62c39cb44917de0772fefd876e170729428142c21d4f17\
            9f72fcdc1c1ff5f13e272449ac9ff01a74e95bb011045b12bdac942b46168d051\
            1ecbb4651d9ddd6491437a8d6b6e6e6877038ea4317a5de863e237ff6472014d2\
            2c88863b6d8de3eb1b73bb46ab12553c2765bcde905487c518936887ba831dc42\
            ca4862bf60b7cccf08ae579f14699fcff5ec8366af5562a2117095dc066105c17\
            714dadae0b2110b91d0f19f062e9ab410f59e4515cb027e268435502cf12d4a2d\
            de1c5b711619507485e54e6e6bb1b279e7f42067c47b124e7b1e044de0345f28c\
            ea642eef79e0da60dad085b9bec8b73c61a4eee59ec4f024fc83366e1efc63762\
            b2c1c214ad151dd01f1a5f16d5a238187f1afdab361dfea2e0956be24b1bcdba7\
            c9a6a5e0296377bd1cf1b722bc4d375ae8aa4761b7aac5a50e9871"
        )
        .unwrap();
    }

    const CHALLENGE: &[u8] = b"challenge";

    fn new_credential_manager() -> CredentialManager {
        let entropy = [0u8; 1];
        CredentialManager::new_with_seed(&entropy)
    }

    #[test]
    fn test_gsk_and_join_msg() {
        let mut cm = new_credential_manager();
        let result = cm.start_join(CHALLENGE);

        let expected_join_msg = hex::decode(
            "04185d9e3a0f0e590928568a951a70749c5f3e\
             969b3c335f109f0e95f4c0cbabe70ddd27e6751\
             df37fa70b906d3d246b388a2a9fb67c3972ea1b\
             822dc80653454e0de86a209418b4953191caa980\
             462463ec21b07da451e7becc2d7917ef34f5150c\
             1c0a4187182af0a43a28868c7b17b2c73704bc26\
             8071b414d99f48999014b2",
        )
        .unwrap();

        assert_eq!(result.gsk.to_bytes().as_slice(), EXPECTED_GSK.as_slice());
        assert_eq!(result.join_msg.to_bytes().as_slice(), &expected_join_msg);
    }

    #[test]
    fn test_finish_join_credentials() {
        let mut cm = new_credential_manager();

        let group_pub_key: GroupPublicKey = GROUP_PUB_KEY.as_slice().try_into().unwrap();
        let gsk: CredentialBIG = EXPECTED_GSK.as_slice().try_into().unwrap();
        let join_response: JoinResponse = hex::decode(
            "04246220e5a9d48d359178c9e0994cc10f7288b50\
            cd059c24c5a26fc5919682e8017b66ca6185d62bf2\
            bed7cf02503157ab93ff79d8d34ab3c48669954b7e\
            2b69c041d98fde59abcd8c0f22790e8d40e253c124\
            0f3697c161d18a9d04ca24ba2b01f0d100b28b3d52\
            9939ec717f4f39e114337878f03c9066afc2250332\
            76f162b4904248822cb548ccb8167480e23f019813\
            4d1547b005ac84c2a7101a4d39c924ee50298022d7\
            dd7c9f0006eab2576635a36af81e0f781437c4ee35\
            b8672511089830401074ad73c4e9e9aed541bdc5a2\
            df2ee815a3ac4f6297b73da35db2a646e19720475c\
            fe50eb2465833b50758f6c8f09fdf645643a4b3ef5\
            bd494be6a551768c81677932196184249f179d319f\
            eba43b32da42501daa355d3cde30615a08ac687188\
            a8c6e3b8a330f76c233e900acd6ef31c50796b9192\
            9cfc16b4fcad40b5309",
        )
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();

        let credentials = cm
            .finish_join(&group_pub_key, &gsk, join_response)
            .unwrap()
            .to_bytes();

        let expected_credentials = hex::decode(
            "04246220e5a9d48d359178c9e0994cc10f7288b50\
            cd059c24c5a26fc5919682e8017b66ca6185d62bf2\
            bed7cf02503157ab93ff79d8d34ab3c48669954b7e\
            2b69c041d98fde59abcd8c0f22790e8d40e253c124\
            0f3697c161d18a9d04ca24ba2b01f0d100b28b3d52\
            9939ec717f4f39e114337878f03c9066afc2250332\
            76f162b4904248822cb548ccb8167480e23f019813\
            4d1547b005ac84c2a7101a4d39c924ee50298022d7\
            dd7c9f0006eab2576635a36af81e0f781437c4ee35\
            b8672511089830401074ad73c4e9e9aed541bdc5a2\
            df2ee815a3ac4f6297b73da35db2a646e19720475c\
            fe50eb2465833b50758f6c8f09fdf645643a4b3ef5\
            bd494be6a551768c8",
        )
        .unwrap();

        assert_eq!(credentials.as_slice(), &expected_credentials);
    }
}
