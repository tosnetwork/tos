#![allow(bare_trait_objects, unused_variables, unused_imports, non_snake_case)]

pub mod collator;
pub mod shard;
pub mod collatorslist;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum Collator_Boxed {
    Engine_Validator_CollatorsList_Collator(crate::tos::engine::validator::collators_list::collator::Collator),
}

impl Eq for Collator_Boxed {}

impl Default for Collator_Boxed {
    fn default() -> Self {
        Collator_Boxed::Engine_Validator_CollatorsList_Collator(
            crate::tos::engine::validator::collators_list::collator::Collator::default(),
        )
    }
}

impl crate::BoxedSerialize for Collator_Boxed {
    fn bare_object(&self) -> &dyn crate::BareSerialize {
        match self {
            Collator_Boxed::Engine_Validator_CollatorsList_Collator(x) => x,
        }
    }
}

impl crate::BoxedDeserialize for Collator_Boxed {
    fn possible_constructors() -> Vec<u32> {
        vec![0xd11f938e]
    }
    fn deserialize_boxed(_id: u32, _de: &mut crate::Deserializer) -> crate::Result<Self> {
        match _id {
            0xd11f938e => Ok(Collator_Boxed::Engine_Validator_CollatorsList_Collator(
                _de.read_bare::<crate::tos::engine::validator::collators_list::collator::Collator>()?,
            )),
            id => _invalid_id!(id),
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum Shard_Boxed {
    Engine_Validator_CollatorsList_Shard(crate::tos::engine::validator::collators_list::shard::Shard),
}

impl Eq for Shard_Boxed {}

impl Default for Shard_Boxed {
    fn default() -> Self {
        Shard_Boxed::Engine_Validator_CollatorsList_Shard(
            crate::tos::engine::validator::collators_list::shard::Shard::default(),
        )
    }
}

impl crate::BoxedSerialize for Shard_Boxed {
    fn bare_object(&self) -> &dyn crate::BareSerialize {
        match self {
            Shard_Boxed::Engine_Validator_CollatorsList_Shard(x) => x,
        }
    }
}

impl crate::BoxedDeserialize for Shard_Boxed {
    fn possible_constructors() -> Vec<u32> {
        vec![0x485c4d7d]
    }
    fn deserialize_boxed(_id: u32, _de: &mut crate::Deserializer) -> crate::Result<Self> {
        match _id {
            0x485c4d7d => Ok(Shard_Boxed::Engine_Validator_CollatorsList_Shard(
                _de.read_bare::<crate::tos::engine::validator::collators_list::shard::Shard>()?,
            )),
            id => _invalid_id!(id),
        }
    }
}
