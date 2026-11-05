// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use alloc::{string::String, vec};

use bytemuck::Pod;
use risc0_zkvm_platform::WORD_SIZE;
use serde::de::{DeserializeOwned, DeserializeSeed, IntoDeserializer, Visitor};

use super::err::{Error, Result};
use crate::align_up;

pub trait WordRead {

    // Reads words.
    fn read_words(&mut self, words: &mut [u32]) -> Result<()>;

    // Reads padded bytes.
    fn read_padded_bytes(&mut self, bytes: &mut [u8]) -> Result<()>;
}

impl<R: WordRead + ?Sized> WordRead for &mut R {

    // Reads words.
    fn read_words(&mut self, words: &mut [u32]) -> Result<()> {
        (**self).read_words(words)
    }

    // Reads padded bytes.
    fn read_padded_bytes(&mut self, bytes: &mut [u8]) -> Result<()> {
        (**self).read_padded_bytes(bytes)
    }
}

impl WordRead for &[u32] {

    // Reads words.
    fn read_words(&mut self, out: &mut [u32]) -> Result<()> {
        if out.len() > self.len() {
            Err(Error::DeserializeUnexpectedEnd)
        } else {
            out.clone_from_slice(&self[..out.len()]);
            (_, *self) = self.split_at(out.len());
            Ok(())
        }
    }

    // Reads padded bytes.
    fn read_padded_bytes(&mut self, out: &mut [u8]) -> Result<()> {
        let bytes: &[u8] = bytemuck::cast_slice(self);
        if out.len() > bytes.len() {
            Err(Error::DeserializeUnexpectedEnd)
        } else {
            out.clone_from_slice(&bytes[..out.len()]);
            (_, *self) = self.split_at(align_up(out.len(), WORD_SIZE) / WORD_SIZE);
            Ok(())
        }
    }
}

// Implements from slice.
pub fn from_slice<T: DeserializeOwned, P: Pod>(slice: &[P]) -> Result<T> {
    match bytemuck::try_cast_slice(slice) {
        Ok(slice) => {
            let mut deserializer = Deserializer::new(slice);
            T::deserialize(&mut deserializer)
        }

        Err(bytemuck::PodCastError::TargetAlignmentGreaterAndInputNotAligned) => {
            let vec = bytemuck::allocation::pod_collect_to_vec::<P, u32>(slice);
            let mut deserializer = Deserializer::new(vec.as_slice());
            T::deserialize(&mut deserializer)
        }
        Err(ref e) => panic!("failed to cast or read slice as [u32]: {e}"),
    }
}

pub struct Deserializer<'de, R: WordRead + 'de> {
    reader: R,
    phantom: core::marker::PhantomData<&'de ()>,
}

struct SeqAccess<'a, 'de, R: WordRead + 'de> {
    deserializer: &'a mut Deserializer<'de, R>,
    len: usize,
}

impl<'de, R: WordRead + 'de> serde::de::SeqAccess<'de> for SeqAccess<'_, 'de, R> {
    type Error = Error;

    // Implements next element seed.
    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: DeserializeSeed<'de>,
    {
        if self.len > 0 {
            self.len -= 1;
            Ok(Some(DeserializeSeed::deserialize(
                seed,
                &mut *self.deserializer,
            )?))
        } else {
            Ok(None)
        }
    }

    // Implements size hint.
    fn size_hint(&self) -> Option<usize> {
        Some(self.len)
    }
}

impl<'de, R: WordRead + 'de> serde::de::VariantAccess<'de> for &'_ mut Deserializer<'de, R> {
    type Error = Error;

    // Implements unit variant.
    fn unit_variant(self) -> Result<()> {
        Ok(())
    }

    // Implements newtype variant seed.
    fn newtype_variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<V::Value> {
        DeserializeSeed::deserialize(seed, self)
    }

    // Implements tuple variant.
    fn tuple_variant<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value> {
        serde::de::Deserializer::deserialize_tuple(self, len, visitor)
    }

    // Implements struct variant.
    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        serde::de::Deserializer::deserialize_tuple(self, fields.len(), visitor)
    }
}

impl<'de, R: WordRead + 'de> serde::de::EnumAccess<'de> for &'_ mut Deserializer<'de, R> {
    type Error = Error;
    type Variant = Self;

    // Implements variant seed.
    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, Self)> {
        let tag = self.try_take_word()?;
        let val = DeserializeSeed::deserialize(seed, tag.into_deserializer())?;
        Ok((val, self))
    }
}

struct MapAccess<'a, 'de, R: WordRead + 'de> {
    deserializer: &'a mut Deserializer<'de, R>,
    len: usize,
}

impl<'a, 'de: 'a, R: WordRead + 'de> serde::de::MapAccess<'de> for MapAccess<'a, 'de, R> {
    type Error = Error;

    // Implements next key seed.
    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>> {
        if self.len > 0 {
            self.len -= 1;
            Ok(Some(DeserializeSeed::deserialize(
                seed,
                &mut *self.deserializer,
            )?))
        } else {
            Ok(None)
        }
    }

    // Implements next value seed.
    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value> {
        DeserializeSeed::deserialize(seed, &mut *self.deserializer)
    }

    // Implements size hint.
    fn size_hint(&self) -> Option<usize> {
        Some(self.len)
    }
}

impl<'de, R: WordRead + 'de> Deserializer<'de, R> {

    // Creates the operation result.
    pub fn new(reader: R) -> Self {
        Deserializer {
            reader,
            phantom: core::marker::PhantomData,
        }
    }

    // Implements try take word.
    fn try_take_word(&mut self) -> Result<u32> {
        let mut val = 0u32;
        self.reader.read_words(core::slice::from_mut(&mut val))?;
        Ok(val)
    }

    // Implements try take dword.
    fn try_take_dword(&mut self) -> Result<u64> {
        let low = self.try_take_word()? as u64;
        let high = self.try_take_word()? as u64;
        Ok(low | (high << 32))
    }
}

impl<'de, R: WordRead + 'de> serde::Deserializer<'de> for &'_ mut Deserializer<'de, R> {
    type Error = Error;

    // Checks human readable.
    fn is_human_readable(&self) -> bool {
        false
    }

    // Deserializes any.
    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::NotSupported)
    }

    // Deserializes bool.
    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let val = match self.try_take_word()? {
            0 => false,
            1 => true,
            _ => return Err(Error::DeserializeBadBool),
        };
        visitor.visit_bool(val)
    }

    // Deserializes i8.
    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i32(self.try_take_word()? as i32)
    }

    // Deserializes i16.
    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i32(self.try_take_word()? as i32)
    }

    // Deserializes i32.
    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i32(self.try_take_word()? as i32)
    }

    // Deserializes i64.
    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i64(self.try_take_dword()? as i64)
    }

    // Deserializes i128.
    fn deserialize_i128<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let mut bytes = [0u8; 16];
        self.reader.read_padded_bytes(&mut bytes)?;
        visitor.visit_i128(i128::from_le_bytes(bytes))
    }

    // Deserializes u8.
    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u32(self.try_take_word()?)
    }

    // Deserializes u16.
    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u32(self.try_take_word()?)
    }

    // Deserializes u32.
    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u32(self.try_take_word()?)
    }

    // Deserializes u64.
    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u64(self.try_take_dword()?)
    }

    // Deserializes u128.
    fn deserialize_u128<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let mut bytes = [0u8; 16];
        self.reader.read_padded_bytes(&mut bytes)?;
        visitor.visit_u128(u128::from_le_bytes(bytes))
    }

    // Deserializes f32.
    fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_f32(f32::from_bits(self.try_take_word()?))
    }

    // Deserializes f64.
    fn deserialize_f64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_f64(f64::from_bits(self.try_take_dword()?))
    }

    // Deserializes char.
    fn deserialize_char<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let c = char::from_u32(self.try_take_word()?).ok_or(Error::DeserializeBadChar)?;
        visitor.visit_char(c)
    }

    // Deserializes str.
    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let len_bytes = self.try_take_word()? as usize;

        let mut bytes = vec![0u8; len_bytes];
        self.reader.read_padded_bytes(&mut bytes)?;
        visitor.visit_string(String::from_utf8(bytes).map_err(|_| Error::DeserializeBadChar)?)
    }

    // Deserializes string.
    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    // Deserializes bytes.
    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let len_bytes = self.try_take_word()? as usize;

        let mut bytes = vec![0u8; len_bytes];
        self.reader.read_padded_bytes(&mut bytes)?;
        visitor.visit_byte_buf(bytes)
    }

    // Deserializes byte buf.
    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_bytes(visitor)
    }

    // Deserializes option.
    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        match self.try_take_word()? {
            0 => visitor.visit_none(),
            1 => visitor.visit_some(self),
            _ => Err(Error::DeserializeBadOption),
        }
    }

    // Deserializes unit.
    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }

    // Deserializes unit struct.
    fn deserialize_unit_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_unit(visitor)
    }

    // Deserializes newtype struct.
    fn deserialize_newtype_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    // Deserializes seq.
    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let len = self.try_take_word()? as usize;
        visitor.visit_seq(SeqAccess {
            deserializer: self,
            len,
        })
    }

    // Deserializes tuple.
    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_seq(SeqAccess {
            deserializer: self,
            len,
        })
    }

    // Deserializes tuple struct.
    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_tuple(len, visitor)
    }

    // Deserializes map.
    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let len = self.try_take_word()? as usize;
        visitor.visit_map(MapAccess {
            deserializer: self,
            len,
        })
    }

    // Deserializes struct.
    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_tuple(fields.len(), visitor)
    }

    // Deserializes enum.
    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_enum(self)
    }

    // Deserializes identifier.
    fn deserialize_identifier<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::NotSupported)
    }

    // Deserializes ignored any.
    fn deserialize_ignored_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::NotSupported)
    }
}

#[cfg(test)]
mod tests {
    use core::f32;

    use alloc::{string::String, vec::Vec};

    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct SomeStruct {}

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum MyEnum {
        MyUnaryConstructor(Vec<u8>),
        MyBinaryConstructor(Vec<u8>, SomeStruct),
    }

    #[test]

    // Tests enum unary.
    fn test_enum_unary() {
        let a = MyEnum::MyUnaryConstructor(vec![1, 2, 3, 4, 5]);
        let encoded = crate::serde::to_vec(&a).unwrap();
        let decoded: MyEnum = from_slice(&encoded).unwrap();
        assert_eq!(a, decoded);
    }

    #[test]

    // Tests enum binary.
    fn test_enum_binary() {
        let a = MyEnum::MyBinaryConstructor(vec![1, 2, 3, 4, 5], SomeStruct {});
        let encoded = crate::serde::to_vec(&a).unwrap();
        let decoded: MyEnum = from_slice(&encoded).unwrap();
        assert_eq!(a, decoded);
    }

    #[test]

    // Tests struct.
    fn test_struct() {
        use serde::Deserialize;

        #[derive(Deserialize, PartialEq, Debug)]
        struct Test {
            bool: bool,
            i8: i8,
            u8: u8,
            i16: i16,
            u16: u16,
            i32: i32,
            u32: u32,
            f32: f32,
            i64: i64,
            u64: u64,
            f64: f64,
        }

        let words = [
            1,
            -4_i32 as u32,
            4,
            -5_i32 as u32,
            5,
            -6_i32 as u32,
            6,
            f32::to_bits(f32::consts::PI),
            -7_i32 as u32,
            0xffffffff,
            7,
            0x00000000,
            f64::to_bits(2.71).checked_rem(0x100000000).unwrap() as u32,
            f64::to_bits(2.71).checked_shr(32).unwrap() as u32,
        ];
        let expected = Test {
            bool: true,
            i8: -4,
            u8: 4,
            i16: -5,
            u16: 5,
            i32: -6,
            u32: 6,
            f32: f32::consts::PI,
            i64: -7,
            u64: 7,
            f64: 2.71,
        };
        assert_eq!(expected, from_slice(&words).unwrap());
    }

    #[test]

    // Tests str.
    fn test_str() {
        use serde::Deserialize;

        #[derive(Deserialize, PartialEq, Debug)]
        struct Test {
            first: String,
            second: String,
        }

        let words = [1, 0x00000061, 3, 0x00636261];
        let expected = Test {
            first: "a".into(),
            second: "abc".into(),
        };
        assert_eq!(expected, from_slice(&words).unwrap());
    }
}
