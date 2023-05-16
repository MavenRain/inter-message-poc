use {
    derive_more::{From, Into, TryInto},
    frost_dalek::{
        compute_message_hash, generate_commitment_share_lists,
        DistributedKeyGeneration, Parameters, Participant,
        SignatureAggregator,
    },
    hash32::{Hasher as _, Murmur3Hasher},
    many_identity::{Address as InnerAddress, Identity},
    many_identity_dsa::ed25519::generate_random_ed25519_identity,
    minicbor::{Decode, Encode},
    rand::rngs::OsRng,
    std::{
        collections::HashMap,
        hash::{Hash, Hasher},
    },
};

#[derive(Clone, Copy, Decode, Encode, From, Into)]
struct Address(#[n(0)] InnerAddress);
impl Hash for Address {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_vec().hash(state)
    }
}

impl From<Address> for u32 {
    fn from(address: Address) -> Self {
        let mut hasher = Murmur3Hasher::default();
        address.hash(&mut hasher);
        hasher.finish32()
    }
}

fn generate_address() -> Address {
    generate_random_ed25519_identity().address().into()
}

#[derive(Debug, From, TryInto)]
enum Error {
    Dalek(ed25519_dalek::ed25519::Error),
    KeyGen(Vec<u32>),
    Threshold(HashMap<u32, String>),
    Unspecified(()),
}

impl Clone for Error {
    fn clone(&self) -> Self {
        use crate::Error::{Dalek, KeyGen, Threshold, Unspecified};
        match self {
            Dalek(_) | Unspecified(_) => Unspecified(()),
            KeyGen(bytes) => KeyGen(bytes.clone()),
            Threshold(dictionary) => Threshold(dictionary.clone()),
        }
    }
}

fn get_threshold_signature_for_2_of_3() -> Result<(), Error> {
    let parameters = Parameters { n: 3, t: 2 };
    let p1_index = generate_address();
    let p2_index = generate_address();
    let p3_index = generate_address();
    let (p1, coefficients1) = Participant::new(&parameters, p1_index.into());
    println!("p1 registered as a participant");
    let (p2, coefficients2) = Participant::new(&parameters, p2_index.into());
    println!("p2 registered as a participant");
    let (p3, coefficients3) = Participant::new(&parameters, p3_index.into());
    println!("p3 registered as a participant");
    p1.public_key().ok_or(()).and_then(|p1_public_key| p1.proof_of_secret_key.verify(&p1.index, p1_public_key))?;
    println!("p1 proof-of-knowledge of secret key verified");
    p2.public_key().ok_or(()).and_then(|p2_public_key| p2.proof_of_secret_key.verify(&p2.index, p2_public_key))?;
    println!("p2 proof-of-knowledge of secret key verified");
    p3.public_key().ok_or(()).and_then(|p3_public_key| p3.proof_of_secret_key.verify(&p3.index, p3_public_key))?;
    println!("p3 proof-of-knowledge of secret key verified");
    let p1_state = DistributedKeyGeneration::new(
        &parameters,
        &p1.index,
        &coefficients1,
        &mut vec![p2.clone(), p3.clone()],
    )
    .map_err(Error::from);
    println!("p1 enters key generation protocol");
    let p2_state = DistributedKeyGeneration::new(
        &parameters,
        &p2.index,
        &coefficients2,
        &mut vec![p1.clone(), p3.clone()],
    )
    .map_err(Error::from);
    println!("p2 enters key generation protocol");
    let p3_state = DistributedKeyGeneration::new(
        &parameters,
        &p3.index,
        &coefficients3,
        &mut vec![p1.clone(), p2.clone()],
    )
    .map_err(Error::from);
    println!("p3 enters key generation protocol");
    let p1_peer_secrets: Result<Vec<_>, _> = p1_state.clone().and_then(|state| {
        state
            .their_secret_shares()
            .map(|shares| shares.iter().cloned().collect())
            .map_err(Error::from)
    });
    println!("p1 collects secret shares to be distributed to other participants");
    let p2_peer_secrets: Result<Vec<_>, _> = p2_state.clone().and_then(|state| {
        state
            .their_secret_shares()
            .map(|shares| shares.iter().cloned().collect())
            .map_err(Error::from)
    });
    println!("p2 collects secret shares to be distributed to other participants");
    let p3_peer_secrets: Result<Vec<_>, _> = p3_state.clone().and_then(|state| {
        state
            .their_secret_shares()
            .map(|shares| shares.iter().cloned().collect())
            .map_err(Error::from)
    });
    println!("p3 collects secret shares to be distributed to other participants");
    p2_peer_secrets
        .clone()
        .and_then(|p2_peer_secrets| {
            p3_peer_secrets
                .clone()
                .map(|p3_peer_secrets| vec![p2_peer_secrets[0].clone(), p3_peer_secrets[0].clone()])
        })
        .and_then(|p1_secret_shares| {
            println!("p1 now has a collection of secret shares given to it by other participants");
            p1_peer_secrets
                .clone()
                .and_then(|p1_peer_secrets| {
                    p3_peer_secrets.map(|p3_peer_secrets| {
                        vec![p1_peer_secrets[0].clone(), p3_peer_secrets[1].clone()]
                    })
                })
                .map(|p2_secret_shares| (p1_secret_shares, p2_secret_shares))
        })
        .and_then(|(p1_secret_shares, p2_secret_shares)| {
            println!("p2 now has a collection of secret shares given to it by other participants");
            p1_peer_secrets
                .and_then(|p1_peer_secrets| {
                    p2_peer_secrets.map(|p2_peer_secrets| {
                        vec![p1_peer_secrets[1].clone(), p2_peer_secrets[1].clone()]
                    })
                })
                .map(|p3_secret_shares| (p1_secret_shares, p2_secret_shares, p3_secret_shares))
        })
        .and_then(|(p1_secret_shares, p2_secret_shares, p3_secret_shares)| {
            println!("p3 now has a collection of secret shares given to it by other participants");
            p1_state
                .and_then(|p1_state| p1_state.to_round_two(p1_secret_shares).map_err(Error::from))
                .and_then(|p1_state| {
                    p2_state.and_then(|p2_state| {
                        p2_state
                            .to_round_two(p2_secret_shares)
                            .map(|p2_state| (p1_state, p2_state))
                            .map_err(Error::from)
                    })
                })
                .and_then(|(p1_state, p2_state)| {
                    p3_state.and_then(|p3_state| {
                        p3_state
                            .to_round_two(p3_secret_shares)
                            .map(|p3_state| (p1_state, p2_state, p3_state))
                            .map_err(Error::from)
                    })
                })
        })
        .and_then(|(p1_state, p2_state, p3_state)| {
            println!("All participants advance to round 2 of key generation");
            p1.public_key()
                .ok_or(())
                .and_then(|p1_public_key| p1_state.finish(p1_public_key))
                .and_then(|(group_key, p1_sk)| {
                    println!("p1 derives long-lived secret key and group key");
                    p2.public_key()
                        .ok_or(())
                        .and_then(|p2_public_key| p2_state.finish(p2_public_key))
                        .map(|(_, p2_sk)| (group_key, p1_sk, p2_sk))
                })
                .and_then(|(group_key, p1_sk, p2_sk)| {
                    println!("p2 derives long-lived secret key and group key");
                    p3.public_key()
                        .ok_or(())
                        .and_then(|p3_public_key| p3_state.finish(p3_public_key))
                        .map(|(_, p3_sk)| (group_key, p1_sk, p2_sk, p3_sk))
                })
                .map_err(Error::from)
        })
        .and_then(|(group_key, _, p2_sk, p3_sk)| {
            println!("p3 derives long-lived secret key and group key");
            let context = b"context string";
            let message = b"message";
            let (p2_public_comshares, mut p2_secret_comshares) =
                generate_commitment_share_lists(&mut OsRng, p2.index, 1);
            let (p3_public_comshares, mut p3_secret_comshares) =
                generate_commitment_share_lists(&mut OsRng, p3.index, 1);
            let mut signature_aggregator = SignatureAggregator::new(
                parameters,
                group_key,
                context.as_slice(),
                message.as_slice(),
            );
            println!("Untrusted signature aggregator created");
            signature_aggregator.include_signer(
                p2_index.into(),
                p2_public_comshares.commitments[0],
                (&p2_sk).into(),
            );
            println!("p2 signer included in aggregator");
            signature_aggregator.include_signer(
                p3_index.into(),
                p3_public_comshares.commitments[0],
                (&p3_sk).into(),
            );
            println!("p3 signer included in aggregator");
            let signers = signature_aggregator.get_signers();
            let message_hash = compute_message_hash(context.as_slice(), message.as_slice());
            println!("Compute hash of agreed upon message");
            let (p2_partial, p3_partial) = p2_sk
                .sign(
                    &message_hash,
                    &group_key,
                    &mut p2_secret_comshares,
                    0,
                    signers,
                )
                .and_then(|p2_partial| {
                    p3_sk
                        .sign(
                            &message_hash,
                            &group_key,
                            &mut p3_secret_comshares,
                            0,
                            signers,
                        )
                        .map(|p3_partial| (p2_partial, p3_partial))
                })
                .map_err(|_| ())?;
            signature_aggregator.include_partial_signature(p2_partial);
            println!("p2 signs message and sends partial signature to aggregate");
            signature_aggregator.include_partial_signature(p3_partial);
            println!("p3 signs message and sends partial signature to aggregate");
            signature_aggregator
                .finalize()
                .and_then(|aggregator| aggregator.aggregate())
                .map_err(|collection| {
                    collection
                        .into_iter()
                        .map(|(key, value)| (key, value.into()))
                        .collect::<HashMap<_, String>>()
                })
                .map_err(Error::from)
                .and_then(|threshold_signature| {
                    println!("Threshold signature constructed");
                    threshold_signature.verify(&group_key, &message_hash).map_err(Error::from)
                })
                // NB: Frost-dalek is currently incompatible with ed25519 verification
                //
                //.and_then(|threshold_signature| {
                //    threshold_signature.verify(&group_key, &message_hash)?;
                //    Ok(ed25519_dalek::Signature::from(threshold_signature.to_bytes()))
                //})
                //.and_then(|threshold_signature|
                //    ed25519_dalek::PublicKey::from_bytes(&group_key.to_bytes()[..]).map_err(Error::from)
                //        .and_then(|public_key| public_key.verify(&message_hash[..], &threshold_signature).map_err(Error::from))
                //)
        })
}

fn main() -> Result<(), Error> {
    get_threshold_signature_for_2_of_3()?;
    println!("Threshold signature verified");
    Ok(())
}
