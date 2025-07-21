use nova_snark::traits::{Engine, Group};

fn main() {
    // Test what types implement both Engine and Group
    
    // Test pasta types
    println!("Testing pasta types:");
    let _: () = check_engine_group::<nova_snark::provider::PallasEngine, nova_snark::provider::VestaEngine>();
    let _: () = check_group::<nova_snark::provider::pasta::pallas::Point, nova_snark::provider::pasta::vesta::Point>();
    
    // Test bn256 types
    println!("Testing bn256 types:");
    let _: () = check_engine_group::<nova_snark::provider::Bn256EngineKZG, nova_snark::provider::GrumpkinEngine>();
    let _: () = check_group::<nova_snark::provider::bn256_grumpkin::bn256::Point, nova_snark::provider::bn256_grumpkin::grumpkin::Point>();
}

fn check_engine_group<G1, G2>()
where
    G1: Engine<Base = <G2 as Engine>::Scalar> + Group,
    G2: Engine<Base = <G1 as Engine>::Scalar> + Group,
{
    println!("Engine+Group check passed for {} and {}", 
        std::any::type_name::<G1>(), 
        std::any::type_name::<G2>());
}

fn check_group<G1, G2>()
where
    G1: Group,
    G2: Group,
{
    println!("Group check passed for {} and {}", 
        std::any::type_name::<G1>(), 
        std::any::type_name::<G2>());
}
