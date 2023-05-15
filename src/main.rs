use {
    frost_dalek::{keygen::Coefficients, DistributedKeyGeneration, Parameters, Participant},
    hash32::{Hasher as _, Murmur3Hasher},
    many_identity::Address as InnerAddress,
    many_identity_dsa::ed25519::generate_random_ed25519_identity,
    minicbor::{Decode, Encode},
    std::hash::{Hash, Hasher},
};

#[derive(Decode, Encode)]
struct Address(#[n(0)] InnerAddress);

impl Hash for Address {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_vec().hash(state)
    }
}

fn get_hash(address: Address) -> u32 {
    let mut hasher = Murmur3Hasher::default();
    address.hash(&mut hasher);
    hasher.finish32()
}

fn get_proofs(participant1: Address, participant2: Address, participant3: Address) {
    let parameters = Parameters { n: 3, t: 2 };
    let (p1, coefficients1) = Participant::new(&parameters, get_hash(participant1));
    let (p2, coefficients2) = Participant::new(&parameters, get_hash(participant2));
    let (p3, coefficients3) = Participant::new(&parameters, get_hash(participant3));
    let p1_state = DistributedKeyGeneration::new(
        &parameters,
        &p1.index,
        &coefficients1,
        &mut vec![p2.clone(), p3.clone()],
    );
    let p2_state = DistributedKeyGeneration::new(
        &parameters,
        &p2.index,
        &coefficients2,
        &mut vec![p1.clone(), p3.clone()],
    );
    let p3_state =
        DistributedKeyGeneration::new(&parameters, &p3.index, &coefficients3, &mut vec![p1, p2]);
    let p1_peer_secrets: Result<Vec<_>, _> = p1_state.map_err(|_| ()).and_then(|state| {
        state
            .their_secret_shares()
            .map(|shares| shares.iter().cloned().collect())
    });
    let p2_peer_secrets: Result<Vec<_>, _> = p2_state.map_err(|_| ()).and_then(|state| {
        state
            .their_secret_shares()
            .map(|shares| shares.iter().cloned().collect())
    });
    let p3_peer_secrets: Result<Vec<_>, _> = p3_state.map_err(|_| ()).and_then(|state| {
        state
            .their_secret_shares()
            .map(|shares| shares.iter().cloned().collect())
    });
    let _ = p2_peer_secrets.and_then(|p2_peer_secrets|
        p3_peer_secrets.map(|p3_peer_secrets| vec![p2_peer_secrets[0].clone(), p3_peer_secrets[0].clone()])
    );
}

fn main() {
    println!("Hello, world!");
}
