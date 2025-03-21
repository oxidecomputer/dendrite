// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

pub trait Summable {
    fn add(self) -> u32;
}

pub struct Checksum {
    sum: u32,
}

impl Checksum {
    pub fn new() -> Self {
        Checksum { sum: 0 }
    }

    pub fn add<T: Summable>(&mut self, val: T) {
        self.sum += val.add();
    }

    pub fn sub<T: Summable>(&mut self, val: T) {
        self.sum -= val.add();
    }

    pub fn sum(&self) -> u16 {
        let mut x = self.sum;

        while x & 0xffff0000 != 0 {
            let carry_count = x >> 16;

            x = (x & 0xffff) + carry_count;
        }
        !(x as u16)
    }
}

impl Default for Checksum {
    fn default() -> Self {
        Self::new()
    }
}

impl Summable for u8 {
    fn add(self) -> u32 {
        self as u32
    }
}

impl Summable for u16 {
    fn add(self) -> u32 {
        self as u32
    }
}

impl Summable for u32 {
    fn add(self) -> u32 {
        (self >> 16) + (self & 0xffff)
    }
}

impl Summable for &[u16] {
    fn add(self) -> u32 {
        let mut sum = 0;
        for a in self {
            sum += *a as u32;
        }
        sum
    }
}

impl Summable for &[u8] {
    fn add(self) -> u32 {
        let mut sum = 0;
        let mut idx = 0;
        while idx < self.len() {
            let mut a = (self[idx] as u32) << 8;
            if idx + 1 < self.len() {
                a |= self[idx + 1] as u32;
            }
            sum += a;
            idx += 2;
        }
        sum
    }
}

impl Summable for &Vec<u8> {
    fn add(self) -> u32 {
        let p: &[u8] = self;
        p.add()
    }
}

impl Summable for (u8, u8) {
    fn add(self) -> u32 {
        let a = self.0 as u32;
        let b = self.1 as u32;

        (a << 8) | b
    }
}
