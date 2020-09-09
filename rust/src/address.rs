use std::fmt::Display;
use std::fmt::{self, Debug};

#[derive(Eq, PartialEq, Hash, Clone)]
pub struct Address {
    pub name: String,
    pub device_id: u64,
    pub device_type: u32,
}

impl Address {
    pub fn new(name: String, device_id: u64, device_type: u32) -> Address {
        Address {
            name,
            device_id,
            device_type,
        }
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "(name: {:?}, device_id: {:?}, device_type: {})",
            self.name, self.device_id, self.device_type
        )
    }
}

impl Display for Address {
    fn fmt(&self, f: &'_ mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(name: {:?}, device_id: {:?}, device_type: {})",
            self.name, self.device_id, self.device_type
        )
    }
}

#[derive(Eq, PartialEq, Hash, Clone)]
pub struct SenderKeyName {
    pub group_id: String,
    pub sender: Address,
}

impl Debug for SenderKeyName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "(group_id: {:?}, sender: {:?})",
            self.group_id, self.sender
        )
    }
}

impl Display for SenderKeyName {
    fn fmt(&self, f: &'_ mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(group_id: {:?}, sender: {:?})",
            self.group_id, self.sender
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn new_address() {
        let _address = Address::new("test".to_string(), 123, 1);
    }
}
