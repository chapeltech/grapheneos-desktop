//! Shared identity and result types for the sole protocol-v3 authority.

/// Fresh Binder/PackageManager observations, never client-supplied identity.
#[derive(Clone, Copy, Debug)]
pub struct Caller<'a> {
    pub uid: i32,
    pub user_id: i32,
    pub package_name: &'a str,
    pub signer_sha256: [u8; 32],
    pub shared_uid: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum Revocation {
    Disabled = 1,
    Undocked = 2,
    Locked = 3,
    UserChanged = 4,
    ClientFailed = 5,
    IdentityChanged = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenError {
    InvalidConfiguration,
    Unauthorized,
    UnsupportedVersion,
    AlreadyOpen,
    Exhausted,
}

/// Accepted means admitted only; the adapter still observes WM completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission { Accepted, Stale, Busy, Revoked }

pub struct IdentityCheck<'a> {
    allowed_package: &'a str,
    allowed_signer: [u8; 32],
}

impl<'a> IdentityCheck<'a> {
    pub fn new(package: &'a str, signer: [u8; 32]) -> Result<Self, OpenError> {
        if package.is_empty() || package.bytes().any(|c| c.is_ascii_whitespace()) {
            return Err(OpenError::InvalidConfiguration);
        }
        Ok(Self { allowed_package: package, allowed_signer: signer })
    }

    pub fn allowed(&self, caller: &Caller<'_>, active_user: i32) -> bool {
        caller.uid >= 0 && caller.user_id >= 0 && !caller.shared_uid &&
            caller.user_id == active_user && caller.uid / 100_000 == caller.user_id &&
            (10_000..=19_999).contains(&(caller.uid % 100_000)) &&
            caller.package_name == self.allowed_package &&
            caller.signer_sha256 == self.allowed_signer
    }
}
