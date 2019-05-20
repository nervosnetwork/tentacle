use bytes::{Bytes, BytesMut};
use snap::{Decoder, Encoder};

const SKIP_COMPRESS_SIZE: usize = 40 * 1024;

#[derive(Clone, Debug)]
struct Message {
    inner: BytesMut,
}

impl Message {
    pub fn init() -> Self {
        Message {
            inner: BytesMut::from(vec![0u8; 8]),
        }
    }

    pub fn compress(&mut self, input: Bytes) {
        if input.len() > SKIP_COMPRESS_SIZE {
            match Encoder::new().compress_vec(&input) {
                Ok(res) => {
                    self.inner.unsplit(BytesMut::from(res));
                    self.set_compress_flag(true);
                }
                Err(_) => {
                    self.inner.unsplit(BytesMut::from(input));
                    self.set_compress_flag(false);
                }
            }
        } else {
            self.set_compress_flag(false);
            self.inner.unsplit(BytesMut::from(input));
        }
    }

    pub fn decompress(&mut self) -> Option<Bytes> {
        if self.inner.len() <= 8 {
            None
        } else if self.compress_flag() {
            match Decoder::new().decompress_vec(&self.inner[8..]) {
                Ok(res) => Some(Bytes::from(res)),
                Err(_) => None,
            }
        } else {
            self.inner.split_to(8);
            Some(self.inner.take().freeze())
        }
    }

    fn set_compress_flag(&mut self, flag: bool) {
        let compress_flag = if flag { 0b1000_0000 } else { 0b0000_0000 };
        self.inner[0] = (self.inner[0] & 0b0111_1111) + (compress_flag & 0b1000_0000);
    }

    fn compress_flag(&self) -> bool {
        (self.inner[0] & 0b1000_0000) != 0
    }

    pub fn into_inner(self) -> Bytes {
        self.inner.freeze()
    }
}

impl From<BytesMut> for Message {
    fn from(src: BytesMut) -> Self {
        Message { inner: src }
    }
}

impl From<Bytes> for Message {
    fn from(src: Bytes) -> Self {
        Message {
            inner: BytesMut::from(src),
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Bytes, Message, SKIP_COMPRESS_SIZE};

    #[test]
    fn test_no_need_compress() {
        let mut msg = Message::init();
        msg.compress(Bytes::from("1222"));

        assert!(!msg.compress_flag());

        let demsg = msg.decompress().unwrap();

        assert_eq!(Bytes::from("1222"), demsg)
    }

    #[test]
    fn test_compress_and_decompress() {
        let mut msg = Message::init();
        let data = Bytes::from(vec![1; SKIP_COMPRESS_SIZE + 1]);
        msg.compress(data.clone());

        assert!(msg.compress_flag());

        let demsg = msg.decompress().unwrap();

        assert_eq!(data, demsg)
    }

    #[test]
    fn test_compress_and_decompress_use_another_message() {
        let mut msg = Message::init();
        let data = Bytes::from(vec![1; SKIP_COMPRESS_SIZE + 1]);
        msg.compress(data.clone());

        assert!(msg.compress_flag());

        let cmp_msg = msg.into_inner();

        let demsg = Into::<Message>::into(cmp_msg).decompress().unwrap();

        assert_eq!(data, demsg)
    }
}
