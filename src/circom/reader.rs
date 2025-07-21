use anyhow::bail;
use byteorder::{LittleEndian, ReadBytesExt};
use std::env::current_dir;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek};
use std::path::Path;
use std::process::Command;
use std::str;

use crate::circom::circuit::R1CS;
use crate::circom::file::{from_reader, read_field};
use crate::FileLocation;
use ff::PrimeField;
use nova_snark::traits::Engine;

pub fn generate_witness_from_bin<Fr: PrimeField>(
    witness_bin: &Path,
    witness_input_json: &String,
    witness_output: &Path,
) -> Vec<Fr> {
    let root = current_dir().unwrap();
    let witness_generator_input = root.join("circom_input.json");
    fs::write(&witness_generator_input, witness_input_json).unwrap();

    let output = Command::new(witness_bin)
        .arg(&witness_generator_input)
        .arg(witness_output)
        .output()
        .expect("failed to execute process");
    if output.stdout.len() > 0 || output.stderr.len() > 0 {
        print!("stdout: {}", str::from_utf8(&output.stdout).unwrap());
        print!("stderr: {}", str::from_utf8(&output.stderr).unwrap());
    }
    let _ = fs::remove_file(witness_generator_input);
    load_witness_from_file(witness_output)
}

/// load witness file by filename (binary format only).
pub fn load_witness_from_file<Fr: PrimeField>(filename: &Path) -> Vec<Fr> {
    load_witness_from_bin_file::<Fr>(filename)
}

/// load witness from bin file by filename
pub fn load_witness_from_bin_file<Fr: PrimeField>(filename: &Path) -> Vec<Fr> {
    let reader = OpenOptions::new()
        .read(true)
        .open(filename)
        .expect("unable to open.");
    load_witness_from_bin_reader::<Fr, BufReader<File>>(BufReader::new(reader))
        .expect("read witness failed")
}

/// load witness from u8 array
pub fn load_witness_from_array<Fr: PrimeField>(buffer: Vec<u8>) -> Result<Vec<Fr>, anyhow::Error> {
    load_witness_from_bin_reader::<Fr, _>(buffer.as_slice())
}

/// load witness from u8 array by a reader
pub(crate) fn load_witness_from_bin_reader<Fr: PrimeField, R: Read>(
    mut reader: R,
) -> Result<Vec<Fr>, anyhow::Error> {
    let mut wtns_header = [0u8; 4];
    reader.read_exact(&mut wtns_header)?;
    if wtns_header != [119, 116, 110, 115] {
        // ruby -e 'p "wtns".bytes' => [119, 116, 110, 115]
        bail!("invalid file header");
    }
    let version = reader.read_u32::<LittleEndian>()?;
    // println!("wtns version {}", version);
    if version > 2 {
        bail!("unsupported file version");
    }
    let num_sections = reader.read_u32::<LittleEndian>()?;
    if num_sections != 2 {
        bail!("invalid num sections");
    }
    // read the first section
    let sec_type = reader.read_u32::<LittleEndian>()?;
    if sec_type != 1 {
        bail!("invalid section type");
    }
    let sec_size = reader.read_u64::<LittleEndian>()?;
    if sec_size != 4 + 32 + 4 {
        bail!("invalid section len")
    }
    let field_size = reader.read_u32::<LittleEndian>()?;
    if field_size != 32 {
        bail!("invalid field byte size");
    }
    let mut prime = vec![0u8; field_size as usize];
    reader.read_exact(&mut prime)?;
    // if prime != hex!("010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430") {
    //     bail!("invalid curve prime {:?}", prime);
    // }
    let witness_len = reader.read_u32::<LittleEndian>()?;
    // println!("witness len {}", witness_len);
    let sec_type = reader.read_u32::<LittleEndian>()?;
    if sec_type != 2 {
        bail!("invalid section type");
    }
    let sec_size = reader.read_u64::<LittleEndian>()?;
    if sec_size != (witness_len * field_size) as u64 {
        bail!("invalid witness section size {}", sec_size);
    }
    let mut result = Vec::with_capacity(witness_len as usize);
    for _ in 0..witness_len {
        result.push(read_field::<&mut R, Fr>(&mut reader)?);
    }
    Ok(result)
}

/// load r1cs file by filename (binary format only)
pub fn load_r1cs<G1, G2>(filename: &FileLocation) -> R1CS<<G1 as Engine>::Scalar>
where
    G1: Engine<Base = <G2 as Engine>::Scalar>,
    G2: Engine<Base = <G1 as Engine>::Scalar>,
{
    let filename = match filename {
        FileLocation::PathBuf(filename) => filename,
        FileLocation::URL(_) => panic!("URL-based R1CS loading is not supported without WASM"),
    };
    load_r1cs_from_bin_file::<G1, G2>(filename)
}

/// load r1cs from bin file by filename
fn load_r1cs_from_bin_file<G1, G2>(filename: &Path) -> R1CS<<G1 as Engine>::Scalar>
where
    G1: Engine<Base = <G2 as Engine>::Scalar>,
    G2: Engine<Base = <G1 as Engine>::Scalar>,
{
    let reader = OpenOptions::new()
        .read(true)
        .open(filename)
        .expect("unable to open.");
    load_r1cs_from_bin::<_, G1, G2>(BufReader::new(reader))
}

/// load r1cs from bin by a reader
pub(crate) fn load_r1cs_from_bin<R: Read + Seek, G1, G2>(reader: R) -> R1CS<<G1 as Engine>::Scalar>
where
    G1: Engine<Base = <G2 as Engine>::Scalar>,
    G2: Engine<Base = <G1 as Engine>::Scalar>,
{
    let file = from_reader::<_, G1, G2>(reader).expect("unable to read.");
    let num_inputs = (1 + file.header.n_pub_in + file.header.n_pub_out) as usize;
    let num_variables = file.header.n_wires as usize;
    let num_aux = num_variables - num_inputs;
    R1CS {
        num_aux,
        num_inputs,
        num_variables,
        constraints: file.constraints,
    }
}
