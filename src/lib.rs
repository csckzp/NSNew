use std::{
    collections::HashMap,
    env::current_dir,
    fs,
    path::{Path, PathBuf},
};

use crate::circom::reader::generate_witness_from_bin;
use circom::circuit::{CircomCircuit, R1CS};
use ff::Field;
use nova_snark::{
    traits::{circuit::TrivialCircuit, Engine},
    nova::{PublicParams, RecursiveSNARK},
};
use num_bigint::BigInt;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod circom;

pub type F<G> = <G as Engine>::Scalar;
pub type EE<G> = nova_snark::provider::ipa_pc::EvaluationEngine<G>;
pub type S<G> = nova_snark::spartan::snark::RelaxedR1CSSNARK<G, EE<G>>;
pub type C1<G> = CircomCircuit<<G as Engine>::Scalar>;
pub type C2<G> = TrivialCircuit<<G as Engine>::Scalar>;

#[derive(Clone)]
pub enum FileLocation {
    PathBuf(PathBuf),
    URL(String),
}

pub fn create_public_params<G1, G2>(r1cs: R1CS<F<G1>>) -> Result<PublicParams<G1, G2, C1<G1>>, Box<dyn std::error::Error>>
where
    G1: Engine<Base = <G2 as Engine>::Scalar>,
    G2: Engine<Base = <G1 as Engine>::Scalar>,
{
    let circuit_primary = CircomCircuit {
        r1cs,
        witness: None,
    };

    let params = PublicParams::setup(&circuit_primary, &|_| 0, &|_| 0)?;
    Ok(params)
}

#[derive(Serialize, Deserialize)]
struct CircomInput {
    step_in: Vec<String>,

    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

fn compute_witness<G1, G2>(
    current_public_input: Vec<String>,
    private_input: HashMap<String, Value>,
    witness_generator_file: FileLocation,
    witness_generator_output: &Path,
) -> Vec<<G1 as Engine>::Scalar>
where
    G1: Engine<Base = <G2 as Engine>::Scalar>,
    G2: Engine<Base = <G1 as Engine>::Scalar>,
{
    let decimal_stringified_input: Vec<String> = current_public_input
        .iter()
        .map(|x| BigInt::from_str_radix(x, 16).unwrap().to_str_radix(10))
        .collect();

    let input = CircomInput {
        step_in: decimal_stringified_input.clone(),
        extra: private_input.clone(),
    };

    let input_json = serde_json::to_string(&input).unwrap();
    
    let witness_generator_file = match &witness_generator_file {
        FileLocation::PathBuf(path) => path,
        FileLocation::URL(_) => panic!("URL-based witness generators are not supported without WASM"),
    };
    
    generate_witness_from_bin::<F<G1>>(
        &witness_generator_file,
        &input_json,
        &witness_generator_output,
    )
}

pub fn create_recursive_circuit<G1, G2>(
    witness_generator_file: FileLocation,
    r1cs: R1CS<F<G1>>,
    private_inputs: Vec<HashMap<String, Value>>,
    start_public_input: Vec<F<G1>>,
    pp: &PublicParams<G1, G2, C1<G1>>,
) -> Result<RecursiveSNARK<G1, G2, C1<G1>>, Box<dyn std::error::Error>>
where
    G1: Engine<Base = <G2 as Engine>::Scalar>,
    G2: Engine<Base = <G1 as Engine>::Scalar>,
{
    let root = current_dir().unwrap();
    let witness_generator_output = root.join("circom_witness.wtns");

    let iteration_count = private_inputs.len();

    let start_public_input_hex = start_public_input
        .iter()
        .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
        .collect::<Vec<String>>();
    let mut current_public_input = start_public_input_hex.clone();

    let witness_0 = compute_witness::<G1, G2>(
        current_public_input.clone(),
        private_inputs[0].clone(),
        witness_generator_file.clone(),
        &witness_generator_output,
    );

    let circuit_0 = CircomCircuit {
        r1cs: r1cs.clone(),
        witness: Some(witness_0),
    };
    let _circuit_secondary: TrivialCircuit<F<G2>> = TrivialCircuit::default();
    let _z0_secondary = vec![<G2 as Engine>::Scalar::ZERO];

    let mut recursive_snark = RecursiveSNARK::<G1, G2, C1<G1>>::new(
        &pp,
        &circuit_0,
        &start_public_input,
    )?;

    for i in 0..iteration_count {
        let witness = compute_witness::<G1, G2>(
            current_public_input.clone(),
            private_inputs[i].clone(),
            witness_generator_file.clone(),
            &witness_generator_output,
        );

        let circuit = CircomCircuit {
            r1cs: r1cs.clone(),
            witness: Some(witness),
        };

        let current_public_output = circuit.get_public_outputs();
        current_public_input = current_public_output
            .iter()
            .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
            .collect();

        let res = recursive_snark.prove_step(
            &pp,
            &circuit,
        );
        assert!(res.is_ok());
    }
    fs::remove_file(witness_generator_output)?;

    Ok(recursive_snark)
}

pub fn continue_recursive_circuit<G1, G2>(
    recursive_snark: &mut RecursiveSNARK<G1, G2, C1<G1>>,
    last_zi: Vec<F<G1>>,
    witness_generator_file: FileLocation,
    r1cs: R1CS<F<G1>>,
    private_inputs: Vec<HashMap<String, Value>>,
    _start_public_input: Vec<F<G1>>,
    pp: &PublicParams<G1, G2, C1<G1>>,
) -> Result<(), Box<dyn std::error::Error>>
where
    G1: Engine<Base = <G2 as Engine>::Scalar>,
    G2: Engine<Base = <G1 as Engine>::Scalar>,
{
    let root = current_dir().unwrap();
    let witness_generator_output = root.join("circom_witness.wtns");

    let iteration_count = private_inputs.len();

    let mut current_public_input = last_zi
        .iter()
        .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
        .collect::<Vec<String>>();

    let _circuit_secondary: TrivialCircuit<F<G2>> = TrivialCircuit::default();
    let _z0_secondary = vec![<G2 as Engine>::Scalar::ZERO];

    for i in 0..iteration_count {
        let witness = compute_witness::<G1, G2>(
            current_public_input.clone(),
            private_inputs[i].clone(),
            witness_generator_file.clone(),
            &witness_generator_output,
        );

        let circuit = CircomCircuit {
            r1cs: r1cs.clone(),
            witness: Some(witness),
        };

        let current_public_output = circuit.get_public_outputs();
        current_public_input = current_public_output
            .iter()
            .map(|&x| format!("{:?}", x).strip_prefix("0x").unwrap().to_string())
            .collect();

        let res = recursive_snark.prove_step(
            pp,
            &circuit,
        );
        assert!(res.is_ok());
    }

    fs::remove_file(witness_generator_output)?;

    Ok(())
}
