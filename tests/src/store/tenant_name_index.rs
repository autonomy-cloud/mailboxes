/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::registry::UnwrapRegistryId;
use migration::tenant_name_index::migrate_tenant_name_index;
use registry::{
    schema::{
        prelude::{ObjectType, Property},
        structs::Tenant,
    },
    types::EnumImpl,
};
use store::{
    RegistryStore,
    backend::ephemeral::EphemeralStore,
    registry::{
        RegistryQuery,
        write::{RegistryWrite, RegistryWriteResult},
    },
    write::{BatchBuilder, RegistryClass, ValueClass},
};
use types::id::Id;

#[tokio::test]
async fn tenant_name_index_backfills_legacy_records_and_enforces_uniqueness() {
    let registry = test_registry().await;
    let tenant = Tenant {
        name: "acme".to_string(),
        ..Default::default()
    };
    let tenant_id = registry
        .write(RegistryWrite::insert(&tenant.clone().into()))
        .await
        .unwrap()
        .unwrap_id(trc::location!());

    clear_tenant_name_index(&registry, "acme").await;
    assert!(
        registry
            .get(ObjectType::Tenant.id(tenant_id))
            .await
            .unwrap()
            .is_some()
    );
    assert!(query_tenant_name(&registry, "acme").await.is_empty());

    migrate_tenant_name_index(&registry).await.unwrap();
    assert_eq!(query_tenant_name(&registry, "acme").await, [tenant_id]);
    assert_eq!(
        registry
            .write(RegistryWrite::insert(&tenant.into()))
            .await
            .unwrap(),
        RegistryWriteResult::PrimaryKeyConflict {
            property: Property::Name,
            existing_id: ObjectType::Tenant.id(tenant_id),
        }
    );
}

#[tokio::test]
async fn tenant_name_index_rejects_legacy_duplicates_before_writing() {
    let registry = test_registry().await;
    for _ in 0..2 {
        registry
            .write(RegistryWrite::insert(
                &Tenant {
                    name: "duplicate".to_string(),
                    ..Default::default()
                }
                .into(),
            ))
            .await
            .unwrap()
            .unwrap_id(trc::location!());
        clear_tenant_name_index(&registry, "duplicate").await;
    }

    assert!(migrate_tenant_name_index(&registry).await.is_err());
    assert!(
        registry
            .primary_key(
                Some(ObjectType::Tenant),
                Property::Name,
                b"duplicate".to_vec(),
            )
            .await
            .unwrap()
            .is_none()
    );
}

async fn test_registry() -> RegistryStore {
    RegistryStore::new(
        ".",
        EphemeralStore::open(),
        "tenant-name-index-test".to_string(),
        0,
        None,
    )
    .await
}

async fn clear_tenant_name_index(registry: &RegistryStore, name: &str) {
    let mut batch = BatchBuilder::new();
    batch.clear(ValueClass::Registry(RegistryClass::PrimaryKey {
        object_id: Some(ObjectType::Tenant.to_id()),
        index_id: Property::Name.to_id(),
        key: name.as_bytes().to_vec(),
    }));
    registry.store().write(batch.build_all()).await.unwrap();
}

async fn query_tenant_name(registry: &RegistryStore, name: &str) -> Vec<Id> {
    registry
        .query(RegistryQuery::new(ObjectType::Tenant).equal_pk(Property::Name, name, true))
        .await
        .unwrap()
}
