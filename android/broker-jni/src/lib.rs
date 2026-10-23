//! Private Kotlin/Rust bridge for the sole protocol-v3 desktop authority.
//! JNI uses std; the decision core remains no_std and forbids unsafe code.
use jni::objects::{JByteArray, JClass, JLongArray};
use jni::sys::{jboolean, jint, jlong};
use jni::JNIEnv;
use wonad_broker_core::layout::Rect;

mod native;

const PACKAGE: &str = "org.wonad.desktop";
const BAD_FRAME: i64 = -100;
const EMPTY_RECT: Rect = Rect { left: 0, top: 0, right: 0, bottom: 0 };

fn read_longs<const N: usize>(
    env: &JNIEnv<'_>,
    array: &JLongArray<'_>,
) -> Option<([i64; N], usize)> {
    let length = usize::try_from(env.get_array_length(array).ok()?).ok()?;
    if length > N { return None; }
    let mut values = [0; N];
    env.get_long_array_region(array, 0, &mut values[..length]).ok()?;
    Some((values, length))
}

#[no_mangle]
pub extern "system" fn Java_org_wonad_desktop_broker_BrokerNative_initialize(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    signer: JByteArray<'_>,
    seed: jlong,
) -> jboolean {
    if env.get_array_length(&signer).ok() != Some(32) { return 0; }
    let mut bytes = [0i8; 32];
    if env.get_byte_array_region(&signer, 0, &mut bytes).is_err() { return 0; }
    let Ok(mut slot) = native::AUTHORITY.lock() else { return 0; };
    if slot.is_some() { return 0; }
    let Ok(authority) = wonad_broker_core::native_authority::Authority::new(
        PACKAGE, bytes.map(|b| b as u8), seed) else { return 0; };
    *slot = Some(authority);
    1
}

#[no_mangle]
pub extern "system" fn Java_org_wonad_desktop_broker_BrokerNative_completion(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    finished: jboolean,
    aborted: jboolean,
    now: jlong,
    deadline: jlong,
    matches: jboolean,
) -> jint {
    use wonad_broker_core::completion::{observe, Completion};
    if finished > 1 || aborted > 1 || matches > 1 { return Completion::TimedOut as jint; }
    observe(finished == 1, aborted == 1, now, deadline, matches == 1) as jint
}

fn int(value: i64) -> Option<i32> { i32::try_from(value).ok() }

fn boolean(value: i64) -> Option<bool> {
    match value { 0 => Some(false), 1 => Some(true), _ => None }
}

fn rect(values: &[i64]) -> Option<Rect> {
    if values.len() != 4 { return None; }
    Some(Rect { left: int(values[0])?, top: int(values[1])?,
        right: int(values[2])?, bottom: int(values[3])? })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_and_booleans_are_checked_before_narrowing() {
        assert_eq!(None, int(i64::MAX));
        assert_eq!(None, int(i64::MIN));
        for value in [-1, 2, 256, i64::MAX] { assert_eq!(None, boolean(value)); }
    }
}
