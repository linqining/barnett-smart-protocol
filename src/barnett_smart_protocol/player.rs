use ark_serialize::CanonicalSerialize;
#[derive(CanonicalSerialize)]
pub struct PlayerInfo {
    pub name: Vec<u8>,
}

impl PlayerInfo {
    pub fn new(name:Vec<u8>) -> Self{
        Self{
            name,
        }
    }
}