use super::TransportErrorV1;
use http_body_util::BodyExt as _;
pub(super) async fn read<B>(mut body: B, limit: Option<usize>) -> Result<Vec<u8>, TransportErrorV1>
where
    B: hyper::body::Body<Data = hyper::body::Bytes> + Unpin,
{
    let mut exact = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| TransportErrorV1::Timeout)?;
        if let Ok(data) = frame.into_data() {
            let length = exact
                .len()
                .checked_add(data.len())
                .ok_or(TransportErrorV1::ResponseTooLarge)?;
            if limit.is_some_and(|limit| length > limit) {
                return Err(TransportErrorV1::ResponseTooLarge);
            }
            exact.extend_from_slice(&data);
        }
    }
    Ok(exact)
}
#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;
    #[tokio::test]
    async fn response_limit_rejects_the_first_oversized_frame() {
        let exact = hyper::body::Bytes::from_static(b"12345");
        assert_eq!(
            read(Full::new(exact), Some(4)).await.unwrap_err(),
            TransportErrorV1::ResponseTooLarge
        );
    }
    #[tokio::test]
    async fn response_limit_preserves_exact_boundary_bytes() {
        assert_eq!(
            read(Full::new(hyper::body::Bytes::from_static(b"1234")), Some(4))
                .await
                .unwrap(),
            b"1234"
        );
    }
}
