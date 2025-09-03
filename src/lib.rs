extern crate alloc;
use alloc::vec::Vec;
use alloy_primitives::{Address, U256};
use alloy_sol_types::sol;
use stylus_sdk::{
    prelude::*,
};

use ark_bn254::{Bn254, Fq, Fr, G1Affine, G2Affine, Fq2};
use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing};
use ark_ff::{PrimeField, Zero, BigInteger};

sol! {
    interface IERC721 {
        function balanceOf(address owner) external view returns (uint256 balance);
        function ownerOf(uint256 tokenId) external view returns (address owner);
        function transferFrom(address from, address to, uint256 tokenId) external;
        function approve(address to, uint256 tokenId) external;
        function getApproved(uint256 tokenId) external view returns (address operator);
        function setApprovalForAll(address operator, bool approved) external;
        function isApprovedForAll(address owner, address operator) external view returns (bool);
    }
}

sol_storage! {
    #[entrypoint]
    pub struct ZKMintContract {
        address owner;
        uint256 next_token_id;
        mapping(uint256 => address) token_owners;
        mapping(address => uint256) token_balances;
        mapping(uint256 => address) token_approvals;
        mapping(address => mapping(address => bool)) operator_approvals;
        
        // Groth16 Verifying Key Storage
        bool vk_initialized;
        
        // Alpha G1 point
        bytes32 vk_alpha_g1_x;
        bytes32 vk_alpha_g1_y;
        
        // Beta G2 point  
        bytes32 vk_beta_g2_x0;
        bytes32 vk_beta_g2_x1;
        bytes32 vk_beta_g2_y0;
        bytes32 vk_beta_g2_y1;
        
        // Gamma G2 point
        bytes32 vk_gamma_g2_x0;
        bytes32 vk_gamma_g2_x1;
        bytes32 vk_gamma_g2_y0;
        bytes32 vk_gamma_g2_y1;
        
        // Delta G2 point
        bytes32 vk_delta_g2_x0;
        bytes32 vk_delta_g2_x1;
        bytes32 vk_delta_g2_y0;
        bytes32 vk_delta_g2_y1;
        
        // Gamma ABC G1 points (for public inputs)
        uint256 vk_gamma_abc_length;
        mapping(uint256 => bytes32) vk_gamma_abc_g1_x;
        mapping(uint256 => bytes32) vk_gamma_abc_g1_y;
    }
}

#[derive(Debug, Clone)]
pub struct ZKProof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}

#[derive(Debug, Clone)]
pub struct VerifyingKey {
    pub alpha_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g2: G2Affine,
    pub gamma_abc_g1: Vec<G1Affine>,
}

impl ZKProof {
    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() != 256 {
            return Err("Invalid proof length");
        }
        
        // Parse G1 point A (64 bytes)
        let a_x = Fq::from_be_bytes_mod_order(&data[0..32]);
        let a_y = Fq::from_be_bytes_mod_order(&data[32..64]);
        let a = G1Affine::new_unchecked(a_x, a_y);
        
        // Parse G2 point B (128 bytes)
        let b_x0 = Fq::from_be_bytes_mod_order(&data[64..96]);
        let b_x1 = Fq::from_be_bytes_mod_order(&data[96..128]);
        let b_y0 = Fq::from_be_bytes_mod_order(&data[128..160]);
        let b_y1 = Fq::from_be_bytes_mod_order(&data[160..192]);
        let b = G2Affine::new_unchecked(
            ark_bn254::Fq2::new(b_x0, b_x1),
            ark_bn254::Fq2::new(b_y0, b_y1),
        );
        
        // Parse G1 point C (64 bytes)
        let c_x = Fq::from_be_bytes_mod_order(&data[192..224]);
        let c_y = Fq::from_be_bytes_mod_order(&data[224..256]);
        let c = G1Affine::new_unchecked(c_x, c_y);
        
        Ok(ZKProof { a, b, c })
    }
}

impl VerifyingKey {
    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        // Expected format: alpha_g1 (64) + beta_g2 (128) + gamma_g2 (128) + delta_g2 (128) + 
        // gamma_abc_length (4) + gamma_abc_points (64 * length)
        if data.len() < 452 { // 64 + 128 + 128 + 128 + 4 = 452 minimum
            return Err("Invalid verifying key length");
        }
        
        let mut offset = 0;
        
        // Parse alpha G1 (64 bytes)
        let alpha_x = Fq::from_be_bytes_mod_order(&data[offset..offset + 32]);
        let alpha_y = Fq::from_be_bytes_mod_order(&data[offset + 32..offset + 64]);
        let alpha_g1 = G1Affine::new_unchecked(alpha_x, alpha_y);
        offset += 64;
        
        // Parse beta G2 (128 bytes)
        let beta_x0 = Fq::from_be_bytes_mod_order(&data[offset..offset + 32]);
        let beta_x1 = Fq::from_be_bytes_mod_order(&data[offset + 32..offset + 64]);
        let beta_y0 = Fq::from_be_bytes_mod_order(&data[offset + 64..offset + 96]);
        let beta_y1 = Fq::from_be_bytes_mod_order(&data[offset + 96..offset + 128]);
        let beta_g2 = G2Affine::new_unchecked(
            Fq2::new(beta_x0, beta_x1),
            Fq2::new(beta_y0, beta_y1),
        );
        offset += 128;
        
        // Parse gamma G2 (128 bytes)
        let gamma_x0 = Fq::from_be_bytes_mod_order(&data[offset..offset + 32]);
        let gamma_x1 = Fq::from_be_bytes_mod_order(&data[offset + 32..offset + 64]);
        let gamma_y0 = Fq::from_be_bytes_mod_order(&data[offset + 64..offset + 96]);
        let gamma_y1 = Fq::from_be_bytes_mod_order(&data[offset + 96..offset + 128]);
        let gamma_g2 = G2Affine::new_unchecked(
            Fq2::new(gamma_x0, gamma_x1),
            Fq2::new(gamma_y0, gamma_y1),
        );
        offset += 128;
        
        // Parse delta G2 (128 bytes)
        let delta_x0 = Fq::from_be_bytes_mod_order(&data[offset..offset + 32]);
        let delta_x1 = Fq::from_be_bytes_mod_order(&data[offset + 32..offset + 64]);
        let delta_y0 = Fq::from_be_bytes_mod_order(&data[offset + 64..offset + 96]);
        let delta_y1 = Fq::from_be_bytes_mod_order(&data[offset + 96..offset + 128]);
        let delta_g2 = G2Affine::new_unchecked(
            Fq2::new(delta_x0, delta_x1),
            Fq2::new(delta_y0, delta_y1),
        );
        offset += 128;
        
        // Parse gamma ABC length (4 bytes)
        if data.len() < offset + 4 {
            return Err("Invalid gamma ABC length");
        }
        let gamma_abc_len = u32::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]) as usize;
        offset += 4;
        
        // Parse gamma ABC G1 points
        if data.len() < offset + (gamma_abc_len * 64) {
            return Err("Invalid gamma ABC points length");
        }
        
        let mut gamma_abc_g1 = Vec::with_capacity(gamma_abc_len);
        for _ in 0..gamma_abc_len {
            let x = Fq::from_be_bytes_mod_order(&data[offset..offset + 32]);
            let y = Fq::from_be_bytes_mod_order(&data[offset + 32..offset + 64]);
            gamma_abc_g1.push(G1Affine::new_unchecked(x, y));
            offset += 64;
        }
        
        Ok(VerifyingKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        })
    }
}

#[public]
impl ZKMintContract {
    #[payable]
    pub fn initialize(&mut self) -> Result<(), Vec<u8>> {
        if self.owner.get() != Address::ZERO {
            return Err("Already initialized".into());
        }
        
        self.owner.set(self.vm().msg_sender());
        self.next_token_id.set(U256::from(1));
        Ok(())
    }
    
    pub fn mint_with_zk_proof(
        &mut self,
        to: Address,
        proof_data: Vec<u8>,
        public_inputs: Vec<U256>,
    ) -> Result<U256, Vec<u8>> {
        // Verify the ZK proof
        if !self.verify_proof(proof_data, public_inputs)? {
            return Err("Invalid ZK proof".into());
        }
        
        let token_id = self.next_token_id.get();
        
        // Mint the token
        self.token_owners.setter(token_id).set(to);
        let current_balance = self.token_balances.get(to);
        self.token_balances.setter(to).set(current_balance + U256::from(1));
        
        // Increment token ID for next mint
        self.next_token_id.set(token_id + U256::from(1));
        
        Ok(token_id)
    }
    
    pub fn verify_proof(
        &self,
        proof_data: Vec<u8>,
        public_inputs: Vec<U256>,
    ) -> Result<bool, Vec<u8>> {
        // Check if verifying key is initialized
        if !self.vk_initialized.get() {
            return Err("Verifying key not initialized".into());
        }

        // Parse the proof from bytes
        let zk_proof = ZKProof::deserialize(&proof_data)
            .map_err(|e| Vec::from(e.as_bytes()))?;
        
        // Convert public inputs to field elements
        let mut field_inputs = Vec::new();
        for input in public_inputs {
            let bytes = input.to_be_bytes::<32>();
            let field_element = Fr::from_be_bytes_mod_order(&bytes);
            field_inputs.push(field_element);
        }
        
        // Load verifying key from storage
        let vk = self.load_verifying_key()?;
        
        // Perform real Groth16 verification
        let is_valid = self.groth16_verify(&zk_proof, &vk, &field_inputs)?;
        
        Ok(is_valid)
    }
    
    // ERC721 view functions
    pub fn balance_of(&self, owner: Address) -> U256 {
        self.token_balances.get(owner)
    }
    
    pub fn owner_of(&self, token_id: U256) -> Result<Address, Vec<u8>> {
        let owner = self.token_owners.get(token_id);
        if owner == Address::ZERO {
            return Err("Token does not exist".into());
        }
        Ok(owner)
    }
    
    pub fn get_next_token_id(&self) -> U256 {
        self.next_token_id.get()
    }

    pub fn set_verifying_key(&mut self, vk_data: Vec<u8>) -> Result<(), Vec<u8>> {
        // Only owner can set verifying key
        if self.vm().msg_sender() != self.owner.get() {
            return Err("Only owner can set verifying key".into());
        }

        let vk = VerifyingKey::deserialize(&vk_data)
            .map_err(|e| Vec::from(e.as_bytes()))?;

        // Store alpha G1
        let alpha_x_bytes = vk.alpha_g1.x().unwrap().into_bigint().to_bytes_be();
        let alpha_y_bytes = vk.alpha_g1.y().unwrap().into_bigint().to_bytes_be();
        let mut alpha_x_array = [0u8; 32];
        let mut alpha_y_array = [0u8; 32];
        alpha_x_array.copy_from_slice(&alpha_x_bytes[..32]);
        alpha_y_array.copy_from_slice(&alpha_y_bytes[..32]);
        self.vk_alpha_g1_x.set(alpha_x_array.into());
        self.vk_alpha_g1_y.set(alpha_y_array.into());

        // Store beta G2
        let beta_x = vk.beta_g2.x().unwrap();
        let beta_y = vk.beta_g2.y().unwrap();
        let mut beta_x0_array = [0u8; 32];
        let mut beta_x1_array = [0u8; 32];
        let mut beta_y0_array = [0u8; 32];
        let mut beta_y1_array = [0u8; 32];
        beta_x0_array.copy_from_slice(&beta_x.c0.into_bigint().to_bytes_be()[..32]);
        beta_x1_array.copy_from_slice(&beta_x.c1.into_bigint().to_bytes_be()[..32]);
        beta_y0_array.copy_from_slice(&beta_y.c0.into_bigint().to_bytes_be()[..32]);
        beta_y1_array.copy_from_slice(&beta_y.c1.into_bigint().to_bytes_be()[..32]);
        self.vk_beta_g2_x0.set(beta_x0_array.into());
        self.vk_beta_g2_x1.set(beta_x1_array.into());
        self.vk_beta_g2_y0.set(beta_y0_array.into());
        self.vk_beta_g2_y1.set(beta_y1_array.into());

        // Store gamma G2
        let gamma_x = vk.gamma_g2.x().unwrap();
        let gamma_y = vk.gamma_g2.y().unwrap();
        let mut gamma_x0_array = [0u8; 32];
        let mut gamma_x1_array = [0u8; 32];
        let mut gamma_y0_array = [0u8; 32];
        let mut gamma_y1_array = [0u8; 32];
        gamma_x0_array.copy_from_slice(&gamma_x.c0.into_bigint().to_bytes_be()[..32]);
        gamma_x1_array.copy_from_slice(&gamma_x.c1.into_bigint().to_bytes_be()[..32]);
        gamma_y0_array.copy_from_slice(&gamma_y.c0.into_bigint().to_bytes_be()[..32]);
        gamma_y1_array.copy_from_slice(&gamma_y.c1.into_bigint().to_bytes_be()[..32]);
        self.vk_gamma_g2_x0.set(gamma_x0_array.into());
        self.vk_gamma_g2_x1.set(gamma_x1_array.into());
        self.vk_gamma_g2_y0.set(gamma_y0_array.into());
        self.vk_gamma_g2_y1.set(gamma_y1_array.into());

        // Store delta G2
        let delta_x = vk.delta_g2.x().unwrap();
        let delta_y = vk.delta_g2.y().unwrap();
        let mut delta_x0_array = [0u8; 32];
        let mut delta_x1_array = [0u8; 32];
        let mut delta_y0_array = [0u8; 32];
        let mut delta_y1_array = [0u8; 32];
        delta_x0_array.copy_from_slice(&delta_x.c0.into_bigint().to_bytes_be()[..32]);
        delta_x1_array.copy_from_slice(&delta_x.c1.into_bigint().to_bytes_be()[..32]);
        delta_y0_array.copy_from_slice(&delta_y.c0.into_bigint().to_bytes_be()[..32]);
        delta_y1_array.copy_from_slice(&delta_y.c1.into_bigint().to_bytes_be()[..32]);
        self.vk_delta_g2_x0.set(delta_x0_array.into());
        self.vk_delta_g2_x1.set(delta_x1_array.into());
        self.vk_delta_g2_y0.set(delta_y0_array.into());
        self.vk_delta_g2_y1.set(delta_y1_array.into());

        // Store gamma ABC G1 points
        self.vk_gamma_abc_length.set(U256::from(vk.gamma_abc_g1.len()));
        for (i, point) in vk.gamma_abc_g1.iter().enumerate() {
            let x_bytes = point.x().unwrap().into_bigint().to_bytes_be();
            let y_bytes = point.y().unwrap().into_bigint().to_bytes_be();
            let mut x_array = [0u8; 32];
            let mut y_array = [0u8; 32];
            x_array.copy_from_slice(&x_bytes[..32]);
            y_array.copy_from_slice(&y_bytes[..32]);
            self.vk_gamma_abc_g1_x.setter(U256::from(i)).set(x_array.into());
            self.vk_gamma_abc_g1_y.setter(U256::from(i)).set(y_array.into());
        }

        self.vk_initialized.set(true);
        Ok(())
    }

    pub fn is_verifying_key_set(&self) -> bool {
        self.vk_initialized.get()
    }
}

impl ZKMintContract {
    /// Load verifying key from storage
    fn load_verifying_key(&self) -> Result<VerifyingKey, Vec<u8>> {
        // Load alpha G1
        let alpha_x_bytes: [u8; 32] = self.vk_alpha_g1_x.get().into();
        let alpha_y_bytes: [u8; 32] = self.vk_alpha_g1_y.get().into();
        let alpha_x = Fq::from_be_bytes_mod_order(&alpha_x_bytes);
        let alpha_y = Fq::from_be_bytes_mod_order(&alpha_y_bytes);
        let alpha_g1 = G1Affine::new_unchecked(alpha_x, alpha_y);

        // Load beta G2
        let beta_x0_bytes: [u8; 32] = self.vk_beta_g2_x0.get().into();
        let beta_x1_bytes: [u8; 32] = self.vk_beta_g2_x1.get().into();
        let beta_y0_bytes: [u8; 32] = self.vk_beta_g2_y0.get().into();
        let beta_y1_bytes: [u8; 32] = self.vk_beta_g2_y1.get().into();
        let beta_x0 = Fq::from_be_bytes_mod_order(&beta_x0_bytes);
        let beta_x1 = Fq::from_be_bytes_mod_order(&beta_x1_bytes);
        let beta_y0 = Fq::from_be_bytes_mod_order(&beta_y0_bytes);
        let beta_y1 = Fq::from_be_bytes_mod_order(&beta_y1_bytes);
        let beta_g2 = G2Affine::new_unchecked(
            Fq2::new(beta_x0, beta_x1),
            Fq2::new(beta_y0, beta_y1),
        );

        // Load gamma G2
        let gamma_x0_bytes: [u8; 32] = self.vk_gamma_g2_x0.get().into();
        let gamma_x1_bytes: [u8; 32] = self.vk_gamma_g2_x1.get().into();
        let gamma_y0_bytes: [u8; 32] = self.vk_gamma_g2_y0.get().into();
        let gamma_y1_bytes: [u8; 32] = self.vk_gamma_g2_y1.get().into();
        let gamma_x0 = Fq::from_be_bytes_mod_order(&gamma_x0_bytes);
        let gamma_x1 = Fq::from_be_bytes_mod_order(&gamma_x1_bytes);
        let gamma_y0 = Fq::from_be_bytes_mod_order(&gamma_y0_bytes);
        let gamma_y1 = Fq::from_be_bytes_mod_order(&gamma_y1_bytes);
        let gamma_g2 = G2Affine::new_unchecked(
            Fq2::new(gamma_x0, gamma_x1),
            Fq2::new(gamma_y0, gamma_y1),
        );

        // Load delta G2
        let delta_x0_bytes: [u8; 32] = self.vk_delta_g2_x0.get().into();
        let delta_x1_bytes: [u8; 32] = self.vk_delta_g2_x1.get().into();
        let delta_y0_bytes: [u8; 32] = self.vk_delta_g2_y0.get().into();
        let delta_y1_bytes: [u8; 32] = self.vk_delta_g2_y1.get().into();
        let delta_x0 = Fq::from_be_bytes_mod_order(&delta_x0_bytes);
        let delta_x1 = Fq::from_be_bytes_mod_order(&delta_x1_bytes);
        let delta_y0 = Fq::from_be_bytes_mod_order(&delta_y0_bytes);
        let delta_y1 = Fq::from_be_bytes_mod_order(&delta_y1_bytes);
        let delta_g2 = G2Affine::new_unchecked(
            Fq2::new(delta_x0, delta_x1),
            Fq2::new(delta_y0, delta_y1),
        );

        // Load gamma ABC G1 points
        let gamma_abc_length = self.vk_gamma_abc_length.get();
        let mut gamma_abc_g1 = Vec::new();
        
        for i in 0..gamma_abc_length.as_limbs()[0] as u32 {
            let x_bytes: [u8; 32] = self.vk_gamma_abc_g1_x.get(U256::from(i)).into();
            let y_bytes: [u8; 32] = self.vk_gamma_abc_g1_y.get(U256::from(i)).into();
            let x = Fq::from_be_bytes_mod_order(&x_bytes);
            let y = Fq::from_be_bytes_mod_order(&y_bytes);
            gamma_abc_g1.push(G1Affine::new_unchecked(x, y));
        }

        Ok(VerifyingKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        })
    }

    fn groth16_verify(
        &self,
        proof: &ZKProof,
        vk: &VerifyingKey,
        public_inputs: &[Fr],
    ) -> Result<bool, Vec<u8>> {
        if public_inputs.len() + 1 != vk.gamma_abc_g1.len() {
            return Err("Wrong number of public inputs".into());
        }

        // Compute vk_x = gamma_abc_g1[0] + sum(public_inputs[i] * gamma_abc_g1[i+1])
        let mut vk_x = vk.gamma_abc_g1[0];
        
        for (i, input) in public_inputs.iter().enumerate() {
            let gamma_abc_term = vk.gamma_abc_g1[i + 1].mul_bigint(input.into_bigint());
            vk_x = (vk_x + gamma_abc_term.into_affine()).into();
        }

        // Perform pairing check: e(A, B) = e(alpha, beta) * e(vk_x, gamma) * e(C, delta)
        // This is equivalent to: e(A, B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) = 1
        
        // Negate some points for the pairing check
        let neg_alpha = -vk.alpha_g1;
        let neg_vk_x = -vk_x;
        let neg_c = -proof.c;

        // Collect G1 and G2 points for multi-pairing
        let g1_points = [proof.a, neg_alpha, neg_vk_x, neg_c];
        let g2_points = [proof.b, vk.beta_g2, vk.gamma_g2, vk.delta_g2];

        // The verification passes if the product of pairings equals 1 (identity element)
        let result = Bn254::multi_pairing(&g1_points, &g2_points);
        
        Ok(result.is_zero())
    }
}

// Export ABI
sol! {
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    
    error TokenNotExists();
    error NotOwner();
    error InvalidProof();
}

#[cfg(feature = "export-abi")]
pub fn print_from_args() {
    stylus_sdk::abi::export()
}