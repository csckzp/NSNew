// some codes borrowed from https://github.com/poma/zkutil/blob/master/src/r1cs_reader.rs
#![allow(unused_variables, dead_code)]

use crate::circom::circuit::Constraint;
use byteorder::{LittleEndian, ReadBytesExt};
use ff::PrimeField;
use nova_snark::traits::Engine;
use std::{
    collections::HashMap,
    io::{Error, ErrorKind, Read, Result, Seek, SeekFrom},
};

// R1CSFile's header
#[derive(Debug, Default)]
pub struct Header {
    pub field_size: u32,
    pub prime_size: Vec<u8>,
    pub n_wires: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub n_prv_in: u32,
    pub n_labels: u64,
    pub n_constraints: u32,
}

// R1CSFile parse result
#[derive(Debug, Default)]
pub struct R1CSFile<Fr: PrimeField> {
    pub version: u32,
    pub header: Header,
    pub constraints: Vec<Constraint<Fr>>,
    pub wire_mapping: Vec<u64>,
}

pub(crate) fn read_field<R: Read, Fr: PrimeField>(mut reader: R) -> Result<Fr> {
    let mut repr = Fr::ZERO.to_repr();
    for digit in repr.as_mut().iter_mut() {
        // TODO: may need to reverse order?
        *digit = reader.read_u8()?;
    }
    let fr = Fr::from_repr(repr).unwrap();
    Ok(fr)
}

fn read_header<R: Read>(mut reader: R, size: u64) -> Result<Header> {
    let field_size = reader.read_u32::<LittleEndian>()?;
    let mut prime_size = vec![0u8; field_size as usize];
    reader.read_exact(&mut prime_size)?;
    if size != 32 + field_size as u64 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Invalid header section size",
        ));
    }

    Ok(Header {
        field_size,
        prime_size,
        n_wires: reader.read_u32::<LittleEndian>()?,
        n_pub_out: reader.read_u32::<LittleEndian>()?,
        n_pub_in: reader.read_u32::<LittleEndian>()?,
        n_prv_in: reader.read_u32::<LittleEndian>()?,
        n_labels: reader.read_u64::<LittleEndian>()?,
        n_constraints: reader.read_u32::<LittleEndian>()?,
    })
}

fn read_constraint_vec<R: Read, Fr: PrimeField>(
    mut reader: R,
    header: &Header,
) -> Result<Vec<(usize, Fr)>> {
    let n_vec = reader.read_u32::<LittleEndian>()? as usize;
    let mut vec = Vec::with_capacity(n_vec);
    for _ in 0..n_vec {
        vec.push((
            reader.read_u32::<LittleEndian>()? as usize,
            read_field::<&mut R, Fr>(&mut reader)?,
        ));
    }
    Ok(vec)
}

fn read_constraints<R: Read, Fr: PrimeField>(
    mut reader: R,
    size: u64,
    header: &Header,
) -> Result<Vec<Constraint<Fr>>> {
    // todo check section size
    let mut vec = Vec::with_capacity(header.n_constraints as usize);
    for _ in 0..header.n_constraints {
        vec.push((
            read_constraint_vec::<&mut R, Fr>(&mut reader, header)?,
            read_constraint_vec::<&mut R, Fr>(&mut reader, header)?,
            read_constraint_vec::<&mut R, Fr>(&mut reader, header)?,
        ));
    }
    Ok(vec)
}

fn read_map<R: Read>(mut reader: R, size: u64, header: &Header) -> Result<Vec<u64>> {
    if size != header.n_wires as u64 * 8 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Invalid map section size",
        ));
    }
    let mut vec = Vec::with_capacity(header.n_wires as usize);
    for _ in 0..header.n_wires {
        vec.push(reader.read_u64::<LittleEndian>()?);
    }
    if vec[0] != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Wire 0 should always be mapped to 0",
        ));
    }
    Ok(vec)
}

pub fn from_reader<R: Read + Seek, G1, G2>(mut reader: R) -> Result<R1CSFile<<G1 as Engine>::Scalar>>
where
    G1: Engine<Base = <G2 as Engine>::Scalar>,
    G2: Engine<Base = <G1 as Engine>::Scalar>,
{
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if magic != [0x72, 0x31, 0x63, 0x73] {
        // magic = "r1cs"
        return Err(Error::new(ErrorKind::InvalidData, "Invalid magic number"));
    }

    let version = reader.read_u32::<LittleEndian>()?;
    if version != 1 {
        return Err(Error::new(ErrorKind::InvalidData, "Unsupported version"));
    }

    let num_sections = reader.read_u32::<LittleEndian>()?;

    // section type -> file offset
    let mut section_offsets = HashMap::<u32, u64>::new();
    let mut section_sizes = HashMap::<u32, u64>::new();

    // get file offset of each section
    for _ in 0..num_sections {
        let section_type = reader.read_u32::<LittleEndian>()?;
        let section_size = reader.read_u64::<LittleEndian>()?;
        let offset = reader.seek(SeekFrom::Current(0))?;
        section_offsets.insert(section_type, offset);
        section_sizes.insert(section_type, section_size);
        reader.seek(SeekFrom::Current(section_size as i64))?;
    }

    let header_type = 1;
    let constraint_type = 2;
    let wire2label_type = 3;

    reader.seek(SeekFrom::Start(*section_offsets.get(&header_type).unwrap()))?;
    let header = read_header(&mut reader, *section_sizes.get(&header_type).unwrap())?;
    if header.field_size != 32 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "This parser only supports 32-byte fields",
        ));
    }

    // println!("header: {:?}", header);
    // if header.prime_size != hex!("010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430")
    // {
    //     return Err(Error::new(
    //         ErrorKind::InvalidData,
    //         "This parser only supports bn256",
    //     ));
    // }

    reader.seek(SeekFrom::Start(
        *section_offsets.get(&constraint_type).unwrap(),
    ))?;
    let constraints = read_constraints::<&mut R, <G1 as Engine>::Scalar>(
        &mut reader,
        *section_sizes.get(&constraint_type).unwrap(),
        &header,
    )?;

    reader.seek(SeekFrom::Start(
        *section_offsets.get(&wire2label_type).unwrap(),
    ))?;
    let wire_mapping = read_map(
        &mut reader,
        *section_sizes.get(&wire2label_type).unwrap(),
        &header,
    )?;

    Ok(R1CSFile {
        version,
        header,
        constraints,
        wire_mapping,
    })
}

mod tests {
    #[test]
    fn sample() {
        use super::*;
        use hex_literal::hex;
        use std::io::{BufReader, Cursor};

        let data = hex!(
            "
        72316373
        01000000
        03000000
        01000000 40000000 00000000
        20000000
        010000f0 93f5e143 9170b979 48e83328 5d588181 b64550b8 29a031e1 724e6430
        07000000
        01000000
        02000000
        03000000
        e8030000 00000000
        03000000
        02000000 88020000 00000000
        02000000
        05000000 03000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        06000000 08000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000
        00000000 02000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        02000000 14000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000 0C000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        02000000
        00000000 05000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        02000000 07000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000
        01000000 04000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        04000000 08000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        05000000 03000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        02000000
        03000000 2C000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        06000000 06000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        00000000
        01000000
        06000000 04000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000
        00000000 06000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        02000000 0B000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000 05000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        01000000
        06000000 58020000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        03000000 38000000 00000000
        00000000 00000000
        03000000 00000000
        0a000000 00000000
        0b000000 00000000
        0c000000 00000000
        0f000000 00000000
        44010000 00000000
    "
        );

        type G1 = nova_snark::provider::PallasEngine;
        type G2 = nova_snark::provider::VestaEngine;

        let reader = BufReader::new(Cursor::new(&data[..]));
        let file = from_reader::<_, G1, G2>(reader).unwrap();
        assert_eq!(file.version, 1);

        assert_eq!(file.header.field_size, 32);
        assert_eq!(
            file.header.prime_size,
            &hex!("010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430")
        );
        assert_eq!(file.header.n_wires, 7);
        assert_eq!(file.header.n_pub_out, 1);
        assert_eq!(file.header.n_pub_in, 2);
        assert_eq!(file.header.n_prv_in, 3);
        assert_eq!(file.header.n_labels, 0x03e8);
        assert_eq!(file.header.n_constraints, 3);

        assert_eq!(file.constraints.len(), 3);
        assert_eq!(file.constraints[0].0.len(), 2);
        assert_eq!(file.constraints[0].0[0].0, 5);
        // assert_eq!(file.constraints[0].0[0].1, ff::from_hex("0x03").unwrap());
        assert_eq!(file.constraints[2].1[0].0, 0);
        // assert_eq!(file.constraints[2].1[0].1, ff::from_hex("0x06").unwrap());
        assert_eq!(file.constraints[1].2.len(), 0);

        assert_eq!(file.wire_mapping.len(), 7);
        assert_eq!(file.wire_mapping[1], 3);
    }

    #[test]
    fn test_reader_size_fail() {
        use super::*;

        // fn read_header<R: Read>(mut reader: R, size: u64) -> Result<Header>
        let mut buf: Vec<u8> = 32_u32.to_le_bytes().to_vec();
        buf.resize(4 + 32, 0);
        let err = read_header(&mut buf.as_slice(), 32).err().unwrap();
        assert_eq!(err.kind(), ErrorKind::InvalidData)
    }
}
