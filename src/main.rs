extern crate crypto;
extern crate rand;
extern crate time;

use rand::{Rng, OsRng};
use crypto::curve25519::{curve25519_base, curve25519};
use crypto::chacha20poly1305::ChaCha20Poly1305;
use crypto::aead::{AeadEncryptor, AeadDecryptor};

pub enum EncryptError {
    RngInitializationFailed,
}

pub fn encrypt(public_key: &[u8; 32], message: &[u8]) -> Result<Vec<u8>, EncryptError> {
    let mut rng = try!(OsRng::new().map_err(|_| EncryptError::RngInitializationFailed));

    let mut ephemeral_secret_key = [0u8; 32];
    rng.fill_bytes(&mut ephemeral_secret_key[..]);

    let ephemeral_public_key: [u8; 32] = curve25519_base(&ephemeral_secret_key[..]);
    let symmetric_key = curve25519(&ephemeral_secret_key[..], &public_key[..]);

    let mut c = ChaCha20Poly1305::new(&symmetric_key, &[0u8; 8][..], &[]);

    let mut output = vec![0; 32 + 16 + message.len()];
    let mut tag = [0u8; 16];
    c.encrypt(message, &mut output[32+16..], &mut tag[..]);

    for (dest, src) in (&mut output[0..32]).iter_mut().zip( ephemeral_public_key.iter() ) {
        *dest = *src;
    }

    for (dest, src) in (&mut output[32..48]).iter_mut().zip( tag.iter() ) {
        *dest = *src;
    }

    Ok(output)
}

pub enum DecryptError {
    Malformed,
    Invalid,
}

pub fn decrypt(secret_key: &[u8; 32], message: &[u8]) -> Result<Vec<u8>, DecryptError> {
    if message.len() < 48 {
        return Err(DecryptError::Malformed);
    }

    let ephemeral_public_key = &message[0..32];
    let tag = &message[32..48];
    let ciphertext = &message[48..];

    let mut plaintext = vec![0; ciphertext.len()];
    let symmetric_key = curve25519(secret_key, ephemeral_public_key);

    let mut decrypter = ChaCha20Poly1305::new(&symmetric_key[..], &[0u8; 8][..], &[]);
    if !decrypter.decrypt(ciphertext, &mut plaintext[..], tag) {
        return Err(DecryptError::Invalid);
    }

    Ok(plaintext)
}



//#[test]
fn main() {
    let mut secret_key = [0u8; 32];
    OsRng::new().unwrap().fill_bytes(&mut secret_key[..]);

    let public_key = curve25519_base(&secret_key[..]);
    println!("[DEBUG.client]: time: {}, Wanna send my password 'AF0ndLaF0rM3?' over the air...\n", time::precise_time_ns());
    let encrypted_message = encrypt(&public_key, b"AF0ndLaF0rM3?").ok().unwrap();
    println!("[DEBUG.client]: time: {}, Generating an ephemeral asymetric Curve25519 keypair.\n", time::precise_time_ns());
    println!("[DEBUG.client]: time: {}, Encryption done with my ephemeral private Key and server pub key.\n", time::precise_time_ns());
    println!("[DEBUG.client]: time: {}, Now switching to symetric encryption/authentication (chacha20-poly1305).\n", time::precise_time_ns());
    println!("[DEBUG.client]: time: {}, Sending my encrypted password + time OvEr ThE AiR !\n", time::precise_time_ns());

    let decrypted_message = decrypt(&secret_key, &encrypted_message[..]).ok().unwrap();
    println!("[DEBUG.server]: time: {}, Checking time & decrypting the received password...\n", time::precise_time_ns());

    assert_eq!(decrypted_message, b"AF0ndLaF0rM3?".to_vec());
    println!("[DEBUG.server]: time: {}, Decrypted password is {}", time::precise_time_ns(), String::from_utf8(decrypted_message).unwrap());

    {
        // Corrupt the ephemeral public key
        let mut corrupt_1 = encrypted_message.clone();
        corrupt_1[3] ^= 1;
        assert!(decrypt(&secret_key, &corrupt_1[..]).is_err());
    }

    {
        // Corrupt the tag
        let mut corrupt_2 = encrypted_message.clone();
        corrupt_2[35] ^= 1;
        assert!(decrypt(&secret_key, &corrupt_2[..]).is_err());
    }

    {
        // Corrupt the message
        let mut corrupt_3 = encrypted_message.clone();
        corrupt_3[50] ^= 1;
        assert!(decrypt(&secret_key, &corrupt_3[..]).is_err());
    }
}
