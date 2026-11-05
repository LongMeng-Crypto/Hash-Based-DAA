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

//! Utilities for accessing buffers of circuits symbolically.

use alloc::{collections::BTreeMap, string::String, vec::Vec};
#[cfg(not(feature = "std"))]
use alloc::{format, string::ToString};
use core::fmt::{Debug, Formatter, Write};

use anyhow::Result;
use risc0_core::field::Elem;

use crate::core::digest::Digest;

pub struct Reg {
    pub offset: usize,
}

impl Component for Reg {

    // Implements walk.
    fn walk<V: Visitor>(&self, v: &mut V) -> core::fmt::Result {
        v.visit_reg(self.offset)
    }

    // Implements ty name.
    fn ty_name(&self) -> &'static str {
        "reg"
    }
}

#[doc(hidden)]
pub trait Component {

    // Implements walk.
    fn walk<V: Visitor>(&self, v: &mut V) -> core::fmt::Result;

    // Implements ty name.
    fn ty_name(&self) -> &'static str;
}

impl<C: Component, const N: usize> Component for [&C; N] {

    // Implements walk.
    fn walk<V: Visitor>(&self, v: &mut V) -> core::fmt::Result {
        for (n, elem) in self.iter().enumerate() {
            let name = alloc::format!("[{n}]");
            v.visit_component(&name, *elem)?;
        }
        Ok(())
    }

    // Implements ty name.
    fn ty_name(&self) -> &'static str {
        "array"
    }
}

#[doc(hidden)]
pub trait Visitor {

    // Implements visit component.
    fn visit_component(&mut self, name: &str, component: &impl Component) -> core::fmt::Result;

    // Implements visit reg.
    fn visit_reg(&mut self, offset: usize) -> core::fmt::Result;
}

#[derive(Clone, Copy)]
pub struct Tree<'a, E: Elem + Into<u32>, C: Component> {
    pub buf: &'a [E],
    pub component: &'a C,
}

impl<'a, E: Elem + Into<u32>, C: Component> Tree<'a, E, C> {

    // Creates the operation result.
    pub fn new(buf: &'a [E], component: &'a C) -> Self {
        Tree { buf, component }
    }

    // Implements map.
    pub fn map<SUBC: Component>(&self, f: impl FnOnce(&'a C) -> &'a SUBC) -> Tree<'a, E, SUBC> {
        Tree {
            buf: self.buf,
            component: f(self.component),
        }
    }

    // Returns u32s.
    pub fn get_u32s(&self) -> Result<Vec<u32>> {
        let mut gather = TreeGather::new(self.buf);
        self.component
            .walk(&mut gather)
            .map_err(anyhow::Error::msg)?;
        Ok(gather.vals)
    }

    // Returns bytes.
    pub fn get_bytes(&self) -> Result<Vec<u8>> {
        self.get_u32s()?
            .into_iter()
            .map(|val| u8::try_from(val).map_err(anyhow::Error::msg))
            .collect()
    }

    // Returns shorts.
    pub fn get_shorts(&self) -> Result<Vec<u16>> {
        self.get_u32s()?
            .into_iter()
            .map(|val| u16::try_from(val).map_err(anyhow::Error::msg))
            .collect()
    }

    // Returns digest from shorts.
    pub fn get_digest_from_shorts(&self) -> Result<Digest> {
        let bytes: Vec<_> = self
            .get_shorts()?
            .into_iter()
            .flat_map(|short| short.to_le_bytes())
            .collect();
        Digest::try_from(bytes.as_slice()).map_err(anyhow::Error::msg)
    }

    // Returns u32 from bytes.
    pub fn get_u32_from_bytes(&self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.get_bytes()?
                .as_slice()
                .try_into()
                .map_err(anyhow::Error::msg)?,
        ))
    }

    // Returns u32 from elem.
    pub fn get_u32_from_elem(&self) -> Result<u32> {
        let u32s = self.get_u32s()?;
        assert_eq!(u32s.len(), 1, "Expecting only a single u32 in {self:?}");
        Ok(u32s[0])
    }
}

// Returns elem.
pub fn get_elem<'a, E>(buf: &'a [E], reg: &Reg) -> &'a E {
    buf.get(reg.offset).expect("Invalid offset in layout")
}

// Returns u32.
pub fn get_u32<E: Copy + Into<u32>>(buf: &[E], reg: &Reg) -> u32 {
    (*get_elem(buf, reg)).into()
}

impl<E: Elem + Into<u32>, C: Component> Debug for Tree<'_, E, C> {

    // Implements fmt.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let mut p = TreePrinter::new(self.buf, Vec::new(), "top");
        self.component.walk(&mut p)?;
        for line in p.lines {
            writeln!(f, "{line}")?;
        }
        Ok(())
    }
}

struct TreePrinter<'a, E: Elem> {
    buf: &'a [E],
    lines: Vec<String>,
    item_count: usize,
    seen: BTreeMap<Vec<String>, String>,
    path: Vec<&'a str>,
}

impl<'a, E: Elem> TreePrinter<'a, E> {

    // Creates the operation result.
    fn new(buf: &'a [E], mut path: Vec<&'a str>, name: &'a str) -> Self {
        path.push(name);
        TreePrinter {
            buf,
            lines: Vec::new(),
            item_count: 0,
            seen: BTreeMap::new(),
            path,
        }
    }
}

impl<E: Elem + Into<u32>> Visitor for TreePrinter<'_, E> {

    // Implements visit component.
    fn visit_component(&mut self, name: &str, component: &impl Component) -> core::fmt::Result {
        match component.ty_name() {
            "U32Reg" => {

                let mut subtree = TreeGather::new(self.buf);
                component.walk(&mut subtree)?;
                if subtree.vals.iter().any(|&x| x != 0) {
                    let mut msg = format!("{name}: ");
                    write!(msg, " 0x")?;
                    for val in subtree.vals {
                        if val > 255 {

                            write!(msg, "[{val:#x}?]")?;
                        } else {
                            write!(msg, "{val:02x}")?;
                        }
                    }
                    self.lines.push(msg);
                    self.item_count += 1;
                }
            }
            _ => {

                let mut subtree = TreePrinter::new(self.buf, self.path.clone(), name);
                component.walk(&mut subtree)?;
                match subtree.item_count {
                    0 => {}
                    1 => {

                        self.item_count += 1;
                        let mut lines = subtree.lines;
                        lines[0] = format!("{name}: {{{}", lines[0]);
                        lines.last_mut().as_mut().unwrap().push_str(" }");
                        self.lines.extend(lines);
                    }
                    _ => {

                        self.item_count += 1;
                        match self.seen.get(&subtree.lines) {
                            Some(path) => {
                                self.lines.push(format!("{name}: duplicate of {path}"));
                            }
                            None => {
                                self.seen.extend(subtree.seen);
                                self.lines.push(format!("{name}: {{"));
                                self.lines
                                    .extend(subtree.lines.iter().map(|s| format!("  {s}")));
                                self.lines.push("}".to_string());
                                self.seen.insert(subtree.lines, subtree.path.join("."));
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    // Implements visit reg.
    fn visit_reg(&mut self, offset: usize) -> core::fmt::Result {
        if let Some(val) = self.buf.get(offset) {
            self.lines.push(format!("{val:?}"));
            self.item_count += 1;
        }
        Ok(())
    }
}

struct TreeGather<'a, E: Elem> {
    buf: &'a [E],
    vals: Vec<u32>,
}

impl<'a, E: Elem> TreeGather<'a, E> {

    // Creates the operation result.
    fn new(buf: &'a [E]) -> Self {
        Self {
            buf,
            vals: Vec::new(),
        }
    }
}

impl<E: Elem + Into<u32>> Visitor for TreeGather<'_, E> {

    // Implements visit component.
    fn visit_component(&mut self, _name: &str, component: &impl Component) -> core::fmt::Result {
        component.walk(self)
    }

    // Implements visit reg.
    fn visit_reg(&mut self, offset: usize) -> core::fmt::Result {
        if let Some(val) = self.buf.get(offset) {
            self.vals.push((*val).into())
        }
        Ok(())
    }
}
