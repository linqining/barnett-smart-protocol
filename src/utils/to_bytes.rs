// use byteorder::{BigEndian, WriteBytesExt};

#[macro_export]
macro_rules! to_bytes {
    ($($x:expr),*) => ({
        let mut buf = vec![];
        $(
            let _ = $x.serialize_compressed(&mut buf).map_err(|e| $crate::error::CardProtocolError::IoError(e.to_string()));
        )*
        Ok(buf)
    })
}


// pub fn U8toBytes(vec: Vec<u8>) -> Vec<u8> {
//     let mut bytes = Vec::<u8>::new();
//     bytes.write_u32::<BigEndian>(self.statement.m as u32).unwrap();
//     bytes.write_u32::<BigEndian>(self.statement.n as u32).unwrap();
//     bytes
// }
