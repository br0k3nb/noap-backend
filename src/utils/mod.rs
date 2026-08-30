pub mod crypto;
pub mod flag;
pub mod geo;
pub mod mail;

pub fn object_id_from_str(s: &str) -> Result<bson::oid::ObjectId, bson::oid::Error> {
    bson::oid::ObjectId::parse_str(s)
}
