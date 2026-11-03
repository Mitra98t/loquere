use crate::IdentityError;

pub(crate) fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], IdentityError> {
    let end = cursor
        .checked_add(N)
        .ok_or(IdentityError::InvalidEncoding)?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or(IdentityError::InvalidEncoding)?;
    let array = slice
        .try_into()
        .map_err(|_| IdentityError::InvalidEncoding)?;
    *cursor = end;
    Ok(array)
}
