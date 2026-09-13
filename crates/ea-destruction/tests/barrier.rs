mod support;
use ea_destruction::*;
use ea_sync_protocol::DestructionStatusResponseV1;
use ea_types::*;
struct Server {
    exact: Vec<u8>,
    organization: OrganizationId,
    id: DestructionId,
}
impl ServerReservationPort for Server {
    fn read_current_status(
        &mut self,
        organization: OrganizationId,
        id: DestructionId,
    ) -> Result<Vec<u8>, DestructionError> {
        assert!(organization == self.organization && id == self.id);
        Ok(self.exact.clone())
    }
}
#[test]
fn confirmation_binds_exact_authorization_and_id_not_the_unsigned_state_code() {
    let f = support::Fixture::new(true, true, false);
    let head = f.head();
    let auth = verify_authorization(&f.authorization(), &head).unwrap();
    let id = auth.fields().destruction_id;
    let status = |id, hash| {
        DestructionStatusResponseV1::new(id, 0, hash, vec![], vec![])
            .unwrap()
            .exact_bytes()
            .to_vec()
    };
    let mut server = Server {
        exact: status(id, auth.object_hash()),
        organization: auth.fields().organization_id,
        id,
    };
    let confirmed = confirm_delivery_barrier(&auth, &mut server).unwrap();
    assert!(confirmed.authorization_hash() == auth.object_hash());
    assert!(confirmed.destruction_id() == id);
    server.exact = status(id, ObjectHash::try_from(&[0x13u8; 32][..]).unwrap());
    assert!(confirm_delivery_barrier(&auth, &mut server).is_err());
    server.exact = status(
        DestructionId::try_from(&[0x12u8; 16][..]).unwrap(),
        auth.object_hash(),
    );
    assert!(confirm_delivery_barrier(&auth, &mut server).is_err());
    server.exact = vec![0];
    assert!(confirm_delivery_barrier(&auth, &mut server).is_err());
}
