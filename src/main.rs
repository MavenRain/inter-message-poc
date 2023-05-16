use {
    derive_more::{From, Into, TryInto},
    frost_dalek::{
        compute_message_hash, generate_commitment_share_lists, keygen::Coefficients,
        signature::ThresholdSignature, DistributedKeyGeneration, Parameters, Participant,
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

fn get_threshold_signature_for_2_of_3() -> Result<ed25519_dalek::Signature, Error> {
    let parameters = Parameters { n: 3, t: 2 };
    let p1_index = generate_address();
    let p2_index = generate_address();
    let p3_index = generate_address();
    let (p1, coefficients1) = Participant::new(&parameters, p1_index.into());
    let (p2, coefficients2) = Participant::new(&parameters, p2_index.into());
    let (p3, coefficients3) = Participant::new(&parameters, p3_index.into());
    let p1_state = DistributedKeyGeneration::new(
        &parameters,
        &p1.index,
        &coefficients1,
        &mut vec![p2.clone(), p3.clone()],
    )
    .map_err(Error::from);
    let p2_state = DistributedKeyGeneration::new(
        &parameters,
        &p2.index,
        &coefficients2,
        &mut vec![p1.clone(), p3.clone()],
    )
    .map_err(Error::from);
    let p3_state = DistributedKeyGeneration::new(
        &parameters,
        &p3.index,
        &coefficients3,
        &mut vec![p1.clone(), p2.clone()],
    )
    .map_err(Error::from);
    let p1_peer_secrets: Result<Vec<_>, _> = p1_state.clone().and_then(|state| {
        state
            .their_secret_shares()
            .map(|shares| shares.iter().cloned().collect())
            .map_err(Error::from)
    });
    let p2_peer_secrets: Result<Vec<_>, _> = p2_state.clone().and_then(|state| {
        state
            .their_secret_shares()
            .map(|shares| shares.iter().cloned().collect())
            .map_err(Error::from)
    });
    let p3_peer_secrets: Result<Vec<_>, _> = p3_state.clone().and_then(|state| {
        state
            .their_secret_shares()
            .map(|shares| shares.iter().cloned().collect())
            .map_err(Error::from)
    });
    p2_peer_secrets
        .clone()
        .and_then(|p2_peer_secrets| {
            p3_peer_secrets
                .clone()
                .map(|p3_peer_secrets| vec![p2_peer_secrets[0].clone(), p3_peer_secrets[0].clone()])
        })
        .and_then(|p1_secret_shares| {
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
            p1_peer_secrets
                .and_then(|p1_peer_secrets| {
                    p2_peer_secrets.map(|p2_peer_secrets| {
                        vec![p1_peer_secrets[1].clone(), p2_peer_secrets[1].clone()]
                    })
                })
                .map(|p3_secret_shares| (p1_secret_shares, p2_secret_shares, p3_secret_shares))
        })
        .and_then(|(p1_secret_shares, p2_secret_shares, p3_secret_shares)| {
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
            p1.public_key()
                .ok_or(())
                .and_then(|p1_public_key| p1_state.finish(p1_public_key))
                .and_then(|(group_key, p1_sk)| {
                    p2.public_key()
                        .ok_or(())
                        .and_then(|p2_public_key| p2_state.finish(p2_public_key))
                        .map(|(_, p2_sk)| (group_key, p1_sk, p2_sk))
                })
                .and_then(|(group_key, p1_sk, p2_sk)| {
                    p3.public_key()
                        .ok_or(())
                        .and_then(|p3_public_key| p3_state.finish(p3_public_key))
                        .map(|(_, p3_sk)| (group_key, p1_sk, p2_sk, p3_sk))
                })
                .map_err(Error::from)
        })
        .and_then(|(group_key, p1_sk, p2_sk, p3_sk)| {
            let context = b"context string";
            let message = b"message";
            let (p2_public_comshares, mut p2_secret_comshares) =
                generate_commitment_share_lists(&mut OsRng, 2, 1);
            let (p3_public_comshares, mut p3_secret_comshares) =
                generate_commitment_share_lists(&mut OsRng, 3, 1);
            let mut signature_aggregator = SignatureAggregator::new(
                parameters,
                group_key,
                context.as_slice(),
                message.as_slice(),
            );
            signature_aggregator.include_signer(
                p2_index.into(),
                p2_public_comshares.commitments[0],
                (&p2_sk).into(),
            );
            signature_aggregator.include_signer(
                p3_index.into(),
                p3_public_comshares.commitments[0],
                (&p3_sk).into(),
            );
            let signers = signature_aggregator.get_signers();
            let message_hash = compute_message_hash(context.as_slice(), message.as_slice());
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
            signature_aggregator.include_partial_signature(p3_partial);
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
                    threshold_signature.verify(&group_key, &message_hash);
                    ed25519_dalek::Signature::from_bytes(threshold_signature.to_bytes().as_slice())
                        .map_err(Error::from)
                })
        })
}

fn main() -> Result<(), Error> {
    get_threshold_signature_for_2_of_3()?;
    println!("Threshold signature verified");
    Ok(())
}
