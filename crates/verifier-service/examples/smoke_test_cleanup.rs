//! Removes everything smoke_test_setup.rs created. Not part of the shipped
//! service — throwaway test hygiene only.

use tokio_postgres::NoTls;

const TEST_PRINCIPAL_ID: &str = "principal:smoke-test-throwaway";

#[tokio::main]
async fn main() {
    let database_url =
        std::env::var("AAP_VERIFIER_DATABASE_URL").expect("set AAP_VERIFIER_DATABASE_URL");
    let (client, connection) = tokio_postgres::connect(&database_url, NoTls)
        .await
        .expect("connect");
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {e}");
        }
    });

    let deleted_receipts = client
        .execute(
            "delete from aap_receipts where agent_id = 'smoke-test-device'",
            &[],
        )
        .await
        .expect("delete receipts");
    let deleted_nonces = client
        .execute(
            "delete from aap_nonces where agent_id = 'smoke-test-device'",
            &[],
        )
        .await
        .expect("delete nonces");
    let deleted_delegations = client
        .execute(
            "delete from aap_delegations where subject_id = 'smoke-test-device'",
            &[],
        )
        .await
        .expect("delete delegations");
    let deleted_principal = client
        .execute(
            "delete from aap_principals where principal_id = $1",
            &[&TEST_PRINCIPAL_ID],
        )
        .await
        .expect("delete principal");

    eprintln!(
        "cleaned up: {deleted_receipts} receipt(s), {deleted_nonces} nonce(s), \
         {deleted_delegations} delegation(s), {deleted_principal} principal row(s)"
    );
}
