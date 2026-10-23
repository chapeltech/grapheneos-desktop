//! Geometry shared by protocol-v3 observation and frame validation.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl Rect {
    pub fn valid(self) -> bool {
        self.left >= 0 && self.top >= 0 && self.right > self.left && self.bottom > self.top
    }

    pub fn contains(self, other: Self) -> bool {
        self.valid() && other.valid() && other.left >= self.left && other.top >= self.top &&
            other.right <= self.right && other.bottom <= self.bottom
    }
}
