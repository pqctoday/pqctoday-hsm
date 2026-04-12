use crate::constants::*;
use hmac::{Hmac, Mac};
use k256::elliptic_curve::group::ff::PrimeField;
use p256::elliptic_curve::group::ff::PrimeField as P256PrimeField;
use sha2::Sha512;
use std::vec::Vec;

type HmacSha512 = Hmac<Sha512>;

/// Defines the curve type for derivation
#[derive(Clone, Copy, PartialEq)]
pub enum HDCurve {
    Secp256k1,
    Nist256p1,
    Ed25519,
}

impl HDCurve {
    pub fn from_oid(oid: &[u8]) -> Option<Self> {
        // secp256k1 = 1.3.132.0.10 (0x06 0x05 0x2B 0x81 0x04 0x00 0x0A)
        let oid_secp256k1 = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A];
        // p256 = 1.2.840.10045.3.1.7 (0x06 0x08 0x2A 0x86 0x48 0xCE 0x3D 0x03 0x01 0x07)
        let oid_p256 = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
        // ed25519 = 1.3.101.112 (0x06 0x03 0x2B 0x65 0x70)
        let oid_ed25519 = [0x06, 0x03, 0x2B, 0x65, 0x70];

        if oid == oid_secp256k1 {
            Some(HDCurve::Secp256k1)
        } else if oid == oid_p256 {
            Some(HDCurve::Nist256p1)
        } else if oid == oid_ed25519 {
            Some(HDCurve::Ed25519)
        } else {
            None
        }
    }
}

/// Derive the HD Master Node from a binary seed
pub fn derive_master_node(seed: &[u8], curve: HDCurve) -> Result<(Vec<u8>, Vec<u8>), u32> {
    let key = match curve {
        HDCurve::Secp256k1 => b"Bitcoin seed".as_ref(),
        HDCurve::Nist256p1 => b"Nist256p1 seed".as_ref(),
        HDCurve::Ed25519 => b"ed25519 seed".as_ref(),
    };

    let mut mac = HmacSha512::new_from_slice(key).map_err(|_| CKR_GENERAL_ERROR)?;
    mac.update(seed);
    let result = mac.finalize().into_bytes();

    let priv_key = result[0..32].to_vec();
    let chain_code = result[32..64].to_vec();

    Ok((priv_key, chain_code))
}

/// Derive an HD Child Node from parent node and index
pub fn derive_child_node(
    parent_priv: &[u8],
    chain_code: &[u8],
    index: u32,
    harden: bool,
    curve: HDCurve,
) -> Result<(Vec<u8>, Vec<u8>), u32> {
    let mut mac = HmacSha512::new_from_slice(chain_code).map_err(|_| CKR_GENERAL_ERROR)?;
    let actual_index = if harden {
        index | CKF_BIP32_HARDENED
    } else {
        index
    };

    if curve == HDCurve::Ed25519 {
        if !harden {
            return Err(CKR_MECHANISM_PARAM_INVALID);
        }
        mac.update(&[0x00]);
        mac.update(parent_priv);
        mac.update(&actual_index.to_be_bytes());
        let result = mac.finalize().into_bytes();
        let child_priv = result[0..32].to_vec();
        let child_chain = result[32..64].to_vec();
        return Ok((child_priv, child_chain));
    }

    let mut data = Vec::new();
    if harden {
        data.push(0x00);
        data.extend_from_slice(parent_priv);
    } else {
        if curve == HDCurve::Secp256k1 {
            let secret = k256::SecretKey::from_slice(parent_priv).map_err(|_| CKR_GENERAL_ERROR)?;
            let public = secret.public_key();
            data.extend_from_slice(public.to_sec1_bytes().as_ref());
        } else if curve == HDCurve::Nist256p1 {
            let secret = p256::SecretKey::from_slice(parent_priv).map_err(|_| CKR_GENERAL_ERROR)?;
            let public = secret.public_key();
            data.extend_from_slice(public.to_sec1_bytes().as_ref());
        }
    }
    data.extend_from_slice(&actual_index.to_be_bytes());

    mac.update(&data);
    let result = mac.finalize().into_bytes();
    let il = &result[0..32];
    let child_chain = result[32..64].to_vec();

    if curve == HDCurve::Secp256k1 {
        let il_scalar = k256::Scalar::from_repr(k256::FieldBytes::clone_from_slice(il))
            .into_option()
            .ok_or(CKR_FUNCTION_FAILED)?;
        let parent_scalar =
            k256::Scalar::from_repr(k256::FieldBytes::clone_from_slice(parent_priv))
                .into_option()
                .ok_or(CKR_FUNCTION_FAILED)?;
        let child_scalar = il_scalar + parent_scalar;

        let child_bytes = child_scalar.to_repr().to_vec();
        // check for invalid 0 key (extremely rare)
        if child_bytes.iter().all(|&b| b == 0) {
            return Err(CKR_FUNCTION_FAILED);
        }
        Ok((child_bytes, child_chain))
    } else {
        let il_scalar = p256::Scalar::from_repr(p256::FieldBytes::clone_from_slice(il))
            .into_option()
            .ok_or(CKR_FUNCTION_FAILED)?;
        let parent_scalar =
            p256::Scalar::from_repr(p256::FieldBytes::clone_from_slice(parent_priv))
                .into_option()
                .ok_or(CKR_FUNCTION_FAILED)?;
        let child_scalar = il_scalar + parent_scalar;

        let child_bytes = child_scalar.to_repr().to_vec();
        if child_bytes.iter().all(|&b| b == 0) {
            return Err(CKR_FUNCTION_FAILED);
        }
        Ok((child_bytes, child_chain))
    }
}
