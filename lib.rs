#![cfg_attr(not(feature = "std"), no_std, no_main)]

use ink::prelude::vec::Vec;

#[ink::contract]
mod azero_pay {
    use ink::storage::Mapping;
    use ink::prelude::{
            vec::Vec,
            string::String,
        };

    use crate::{AzeroPayError, Claim};

    #[ink(storage)]
    pub struct AzeroPay {
        pub claims: Mapping<String, Claim>
     }

    impl AzeroPay {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                claims: Mapping::default()
             }
        }

        #[ink(message, payable)]
        pub fn create(&mut self, id: String, public_key: [u8; 33]) -> Result<(), AzeroPayError> {
            if self.claims.contains(&id) {
                return Err(AzeroPayError::AlreadyExists);
            }
            let y = &Claim {
                public_key: Vec::from(public_key),
                value: self.env().transferred_value(),
                redeemed: false
            };

            self.claims.insert(id, y);
            Ok(())
        }

        #[ink(message)]
        pub fn redeem(
            &mut self,
            claim_id: String,
            signature: [u8; 65],
        ) -> Result<(), AzeroPayError> {
            let mut claim = match self.claims.get(&claim_id) {
                Some(x) => x,
                None => return Err(AzeroPayError::NotFound)
            };

            if claim.redeemed {
                return Err(AzeroPayError::AlreadyRedeemed);
            }

            let claim_hash : [u8; 32] = self.env().hash_bytes::<ink::env::hash::Blake2x256>(&scale::Encode::encode(&claim_id));
            let compressed_public_key = self.env().ecdsa_recover(&signature, &claim_hash).unwrap();

            if claim.public_key != compressed_public_key {
                return Err(AzeroPayError::InvalidSignature);
            }

            match self.env().transfer(self.env().caller(), claim.value) {
                Ok(_) => {},
                Err(_) => return Err(AzeroPayError::TransferFailed)
            };

            claim.redeemed = true;
            self.claims.insert(claim_id, &claim);
            Ok(())
        }
    }

    #[cfg(all(test, feature = "e2e-tests"))]
    mod e2e_tests {
        use ink_e2e::{build_message, subxt::config::substrate::BlakeTwo256};
        use ink_e2e::subxt::config::Hasher;
        use rand::Rng;
        use ink::{env::hash::CryptoHash, primitives::AccountId};
        use crate::azero_pay::AzeroPayRef;
        use crate::AzeroPayError;
        type E2EResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

        #[ink_e2e::test]
        async fn send_and_redeem(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            let alice = ink_e2e::alice();
            let mut rng = rand::thread_rng();
            let ecdsa_alice = subxt_signer::ecdsa::Keypair::from_seed(rng.gen()).unwrap();
            let claim_id: String = "test".to_string();
            let message = scale::Encode::encode(&claim_id);
            
            let message_hash: [u8; 32] = sp_core_hashing::blake2_256(&message);
            let signature = ecdsa_alice.sign(&message);
            assert_eq!(true, subxt_signer::ecdsa::verify(&signature, message, &ecdsa_alice.public_key()));
            
            let constructor = AzeroPayRef::new();
            let azero_pay_account_id = client
                .instantiate("azero_pay", &alice, constructor, 0, None)
                .await
                .expect("instantiate failed")
                .account_id;

            let create_message = build_message::<AzeroPayRef>(azero_pay_account_id)
                .call(|contract| contract.create(claim_id.clone(), ecdsa_alice.public_key().0));

            let create_result = client.call(&alice, create_message, 100_000, None)
                .await
                .expect("call failed");

            let redeem_message = build_message::<AzeroPayRef>(azero_pay_account_id)
                .call(|contract| contract.redeem(claim_id.clone(), signature.0));

            let result = client.call(&alice, redeem_message, 0, None)
                .await
                .expect("call failed")
                .return_value()
                .unwrap();

            assert_eq!(result, ());

            let redeem_message = build_message::<AzeroPayRef>(azero_pay_account_id)
                .call(|contract| contract.redeem(claim_id.clone(), signature.0));

            let result = client.call_dry_run(&alice, &redeem_message, 0, None)
                .await
                .return_value()
                .err()
                .unwrap();

            assert_eq!(result, AzeroPayError::AlreadyRedeemed);

            Ok(())
        }

        #[ink_e2e::test]
        async fn send_and_redeem2(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
            let alice = ink_e2e::alice();
            let claim_id: String = "fbc2cc1b-ca79-4a85-a13d-e6eeb194ef0c".to_string();
            
            let public_key = [
                3,
                234,
                55,
                59,
                159,
                61,
                97,
                88,
                134,
                232,
                128,
                24,
                28,
                195,
                77,
                94,
                216,
                127,
                64,
                49,
                191,
                120,
                178,
                203,
                89,
                149,
                138,
                121,
                22,
                151,
                121,
                222,
                27
            ];

            let signature = [
                253,
                172,
                211,
                231,
                72,
                254,
                121,
                40,
                187,
                184,
                119,
                74,
                177,
                198,
                177,
                145,
                192,
                212,
                221,
                176,
                193,
                156,
                99,
                210,
                9,
                70,
                212,
                200,
                236,
                105,
                69,
                143,
                123,
                32,
                201,
                141,
                148,
                201,
                199,
                134,
                246,
                87,
                239,
                55,
                122,
                161,
                242,
                225,
                233,
                24,
                248,
                129,
                195,
                82,
                172,
                207,
                93,
                185,
                71,
                168,
                202,
                251,
                16,
                228,
                0
            ];

            // assert_eq!(true, subxt_signer::ecdsa::verify(&signature, message, &ecdsa_alice.public_key()));
            
            let constructor = AzeroPayRef::new();
            let azero_pay_account_id = client
                .instantiate("azero_pay", &alice, constructor, 0, None)
                .await
                .expect("instantiate failed")
                .account_id;

            let create_message = build_message::<AzeroPayRef>(azero_pay_account_id)
                .call(|contract| contract.create(claim_id.clone(), public_key));

            let create_result = client.call(&alice, create_message, 100_000, None)
                .await
                .expect("call failed");

            let redeem_message = build_message::<AzeroPayRef>(azero_pay_account_id)
                .call(|contract| contract.redeem(claim_id.clone(), signature));

            let result = client.call(&alice, redeem_message, 0, None)
                .await
                .expect("call failed")
                .return_value()
                .unwrap();

            assert_eq!(result, ());

            let redeem_message = build_message::<AzeroPayRef>(azero_pay_account_id)
                .call(|contract| contract.redeem(claim_id.clone(), signature));

            let result = client.call_dry_run(&alice, &redeem_message, 0, None)
                .await
                .return_value()
                .err()
                .unwrap();

            assert_eq!(result, AzeroPayError::AlreadyRedeemed);

            Ok(())
        }

    }
}

#[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub enum AzeroPayError {
    AlreadyExists,
    NotFound,
    InvalidSignature,
    AlreadyRedeemed,
    TransferFailed
}

pub struct ClamimRequest {
    pub claim_id: u128
}

#[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout))]
pub struct Claim {
    pub public_key: Vec<u8>,
    pub redeemed: bool,
    pub value: u128
}


