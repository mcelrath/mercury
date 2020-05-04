//! Transfer
//!
//! Transfer coins in state entity to new owner


// transfer() messages:
// 0. Receiver communicates address to Sender (B2 and C2)
// 1. Sender Initialises transfer protocol with State Entity
//      a. init, authorisation, provide receivers proofkey C2
//      b. State Entity generate x1 and sends to Sender
//      c. Sender and State Entity Co-sign new back up transaction sending to Receivers
//          backup address Addr(B2)
// 2. Receiver performs transfer with State
//      a.

use bitcoin::Transaction;
use super::super::Result;
use crate::wallet::wallet::{ StateEntityAddress, Wallet };
use crate::state_entity::util::{ cosign_tx_input, PrepareSignTxMessage };
use super::super::utilities::requests;

use curv::FE;
use bitcoin::{ PublicKey };

#[derive(Serialize, Debug)]
pub struct TransferMsg1 {
    id: String,
    receiver_proof_key: PublicKey,
}
#[derive(Deserialize, Debug)]
pub struct TransferMsg2 {
    x1: FE,
}

// Transfer coins to new Owner from this wallet
pub fn transfer_sender(wallet: &mut Wallet, shared_wallet_id: &String, receiver_addr: &StateEntityAddress, mut prev_tx_b_prepare_sign_msg: PrepareSignTxMessage) -> Result<(FE, Transaction)> {
    // init transfer: send Receivers proof_key
    let transfer_msg2: TransferMsg2 = requests::postb(&wallet.client_shim,&format!("/transfer/init"),
        &TransferMsg1 {
            id: shared_wallet_id.to_string(),
            receiver_proof_key: receiver_addr.proof_key
        })?;

    // sign new back up tx
    prev_tx_b_prepare_sign_msg.address = receiver_addr.backup_addr.clone();
    let new_tx_b_signed = cosign_tx_input(wallet, &shared_wallet_id, &prev_tx_b_prepare_sign_msg)?;

    Ok((transfer_msg2.x1, new_tx_b_signed))
}

/// Transfer coins from old Owner to this wallet
pub fn transfer_receiver(wallet: &mut Wallet) {


}


#[cfg(test)]
mod tests {

    use curv::elliptic::curves::traits::{ECPoint, ECScalar};
    use curv::{FE, GE};

    #[test]
    fn math() {
        let g: GE = ECPoint::generator();

        //owner1 share
        let o1_s: FE = ECScalar::new_random();

        // SE share
        let s1_s: FE = ECScalar::new_random();
        let s1_p: GE = g * s1_s;

        // deposit P
        let p_p = s1_p*o1_s;
        println!("P1: {:?}",p_p);


        // transfer
        // SE new random key x1
        let x1_s: FE = ECScalar::new_random();

        // owner2 share
        let o2_s: FE = ECScalar::new_random();
        let o2_p: GE = g * o2_s;

        // t1 = o1*x1*o2_inv
        let t1 = o1_s*x1_s*(o2_s.invert());

        // t2 = t1*x1_inv*s1
        let s2_s = t1*(x1_s.invert())*s1_s;

        println!("P2: {:?}",o2_p*s2_s);
    }
}
