/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use registry::{
    schema::{
        prelude::{ObjectType, Property},
        structs::Tenant,
    },
    types::{EnumImpl, id::ObjectId},
};
use std::collections::HashMap;
use store::{
    RegistryStore, SerializeInfallible,
    registry::RegistryQuery,
    write::{BatchBuilder, RegistryClass, ValueClass},
};
use trc::AddContext;

/// Backfills the Tenant/name primary-key index introduced in schema version 7.
///
/// The duplicate-name preflight intentionally completes before the first write. This ensures a
/// legacy database with ambiguous tenant names fails closed rather than partially indexing one of
/// the duplicates. Individual index writes are idempotent so an interrupted or concurrent startup
/// can safely resume the migration.
pub async fn migrate_tenant_name_index(registry: &RegistryStore) -> trc::Result<()> {
    let tenant_ids = registry
        .query::<Vec<types::id::Id>>(RegistryQuery::new(ObjectType::Tenant))
        .await
        .caused_by(trc::location!())?;
    let mut tenants = Vec::with_capacity(tenant_ids.len());
    for tenant_id in tenant_ids {
        let object_id = ObjectType::Tenant.id(tenant_id);
        let tenant = registry
            .object::<Tenant>(tenant_id)
            .await
            .caused_by(trc::location!())?
            .ok_or_else(|| {
                migration_error(format!(
                    "Cannot create the Tenant/name unique index: {object_id} is indexed but its record is missing"
                ))
            })?;
        tenants.push((tenant.name, object_id));
    }

    validate_unique_tenant_names(
        tenants
            .iter()
            .map(|(name, object_id)| (name.as_str(), *object_id)),
    )?;

    for (name, object_id) in tenants {
        ensure_tenant_name_index(registry, &name, object_id).await?;
    }

    Ok(())
}

fn validate_unique_tenant_names<'x>(
    tenants: impl IntoIterator<Item = (&'x str, ObjectId)>,
) -> trc::Result<()> {
    let mut names = HashMap::new();

    for (name, object_id) in tenants {
        if let Some(existing_id) = names.insert(name, object_id) {
            return Err(migration_error(format!(
                "Cannot create the Tenant/name unique index: tenant name {name:?} is used by {existing_id} and {object_id}"
            )));
        }
    }

    Ok(())
}

async fn ensure_tenant_name_index(
    registry: &RegistryStore,
    name: &str,
    object_id: ObjectId,
) -> trc::Result<()> {
    // A second process may be running the same startup migration. Retry after an assertion race,
    // then accept the key only when it points at the same tenant.
    for _ in 0..3 {
        match registry
            .primary_key(
                Some(ObjectType::Tenant),
                Property::Name,
                name.as_bytes().to_vec(),
            )
            .await
            .caused_by(trc::location!())?
        {
            Some(existing_id) if existing_id == object_id => return Ok(()),
            Some(existing_id) => {
                return Err(migration_error(format!(
                    "Cannot create the Tenant/name unique index: tenant name {name:?} belongs to both {existing_id} and {object_id}"
                )));
            }
            None => {}
        }

        let key = ValueClass::Registry(RegistryClass::PrimaryKey {
            object_id: Some(ObjectType::Tenant.to_id()),
            index_id: Property::Name.to_id(),
            key: name.as_bytes().to_vec(),
        });
        let mut batch = BatchBuilder::new();
        batch
            .assert_value(key.clone(), ())
            .set(key, object_id.serialize());

        match registry.store().write(batch.build_all()).await {
            Ok(_) => return Ok(()),
            Err(err) if err.is_assertion_failure() => continue,
            Err(err) => return Err(err.caused_by(trc::location!())),
        }
    }

    Err(migration_error(format!(
        "Cannot create the Tenant/name unique index for {object_id}: concurrent writes did not settle"
    )))
}

fn migration_error(details: String) -> trc::Error {
    trc::StoreEvent::DataCorruption
        .into_err()
        .caused_by(trc::location!())
        .details(details)
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::id::Id;

    #[test]
    fn tenant_name_preflight_rejects_duplicates() {
        let result = validate_unique_tenant_names([
            ("acme", ObjectType::Tenant.id(Id::new(1))),
            ("globex", ObjectType::Tenant.id(Id::new(2))),
            ("acme", ObjectType::Tenant.id(Id::new(3))),
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn tenant_name_preflight_accepts_unique_names() {
        validate_unique_tenant_names([
            ("acme", ObjectType::Tenant.id(Id::new(1))),
            ("globex", ObjectType::Tenant.id(Id::new(2))),
        ])
        .unwrap();
    }
}
