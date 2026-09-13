pub type Hash = [u8; 32];
pub const MAX_OBJECT: usize = 33554432;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub &'static str);
pub trait Wire: Sized {
    const MIN_SIZE: usize;
    fn read(reader: &mut Reader) -> Result<Self, Error>;
    fn write(&self, writer: &mut Writer) -> Result<(), Error>;
}
pub struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
    allocation: usize,
}
impl<'a> Reader<'a> {
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.bytes.len() - self.offset {
            return Err(Error("truncated"));
        }
        let out = &self.bytes[self.offset..self.offset + n];
        self.offset += n;
        Ok(out)
    }
    fn allocate(&mut self, n: usize) -> Result<(), Error> {
        self.allocation = self.allocation.checked_sub(n).ok_or(Error("allocation-bound"))?;
        Ok(())
    }
    pub fn integer(&mut self, width: usize) -> Result<u64, Error> {
        Ok(self.take(width)?.iter().fold(0u64, |n, b| (n << 8) | u64::from(*b)))
    }
    pub fn header(&mut self, tag: &[u8; 4]) -> Result<(), Error> {
        let b = self.take(8)?;
        if b[..4] != tag[..] {
            return Err(Error("tag"));
        }
        if b[4..6] != [0, 1] {
            return Err(Error("version"));
        }
        if b[6..8] != [0, 0] {
            return Err(Error("flags"));
        }
        Ok(())
    }
    pub fn hash(&mut self) -> Result<Hash, Error> {
        let mut h = [0; 32];
        h.copy_from_slice(self.take(32)?);
        Ok(h)
    }
    pub fn blob(&mut self, max: usize) -> Result<Vec<u8>, Error> {
        let n = self.integer(4)? as usize;
        if n > max {
            return Err(Error("blob-bound"));
        }
        self.allocate(n)?;
        Ok(self.take(n)?.to_vec())
    }
    pub fn list<T: Wire>(&mut self, width: usize, max: usize) -> Result<Vec<T>, Error> {
        let n = self.integer(width)? as usize;
        if n > max {
            return Err(Error("list-bound"));
        }
        if T::MIN_SIZE > 0 && n > (self.bytes.len() - self.offset) / T::MIN_SIZE {
            return Err(Error("truncated"));
        }
        self.allocate(n.checked_mul(std::mem::size_of::<T>()).ok_or(Error("allocation-bound"))?)?;
        let mut values = Vec::new();
        values.try_reserve_exact(n).map_err(|_| Error("allocation-bound"))?;
        for _ in 0..n {
            values.push(T::read(self)?);
        }
        Ok(values)
    }
}
pub struct Writer {
    bytes: Vec<u8>,
}
impl Writer {
    pub fn bytes(&mut self, value: &[u8]) -> Result<(), Error> {
        if value.len() > MAX_OBJECT - self.bytes.len() {
            return Err(Error("object-bound"));
        }
        self.bytes.try_reserve(value.len()).map_err(|_| Error("allocation-bound"))?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }
    pub fn integer(&mut self, n: u64, width: usize) -> Result<(), Error> {
        self.bytes(&n.to_be_bytes()[8 - width..])
    }
    pub fn header(&mut self, tag: &[u8; 4]) -> Result<(), Error> {
        self.bytes(tag)?;
        self.bytes(&[0, 1, 0, 0])
    }
    pub fn blob(&mut self, value: &[u8], max: usize) -> Result<(), Error> {
        if value.len() > max {
            return Err(Error("blob-bound"));
        }
        self.integer(value.len() as u64, 4)?;
        self.bytes(value)
    }
    pub fn list<T: Wire>(&mut self, value: &[T], width: usize, max: usize) -> Result<(), Error> {
        if value.len() > max {
            return Err(Error("list-bound"));
        }
        self.integer(value.len() as u64, width)?;
        for v in value {
            v.write(self)?;
        }
        Ok(())
    }
}
impl Wire for Hash {
    const MIN_SIZE: usize = 32;
    fn read(r: &mut Reader) -> Result<Self, Error> {
        r.hash()
    }
    fn write(&self, w: &mut Writer) -> Result<(), Error> {
        w.bytes(self)
    }
}
pub fn decode<T: Wire>(bytes: &[u8]) -> Result<T, Error> {
    if bytes.len() > MAX_OBJECT {
        return Err(Error("object-bound"));
    }
    let mut r = Reader { bytes, offset: 0, allocation: 2 * MAX_OBJECT };
    let value = T::read(&mut r)?;
    if r.offset != bytes.len() {
        return Err(Error("trailing"));
    }
    Ok(value)
}
pub fn encode<T: Wire>(value: &T) -> Result<Vec<u8>, Error> {
    let mut w = Writer { bytes: Vec::new() };
    value.write(&mut w)?;
    Ok(w.bytes)
}
