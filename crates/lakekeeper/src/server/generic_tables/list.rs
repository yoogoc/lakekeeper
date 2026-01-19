use std::{collections::HashMap, sync::Arc};

use crate::{
    api::{
        ApiContext,
        data::v1::generic_tables::{
            GenericTableIdentifier, ListGenericTablesQuery, ListGenericTablesResponse,
        },
        iceberg::v1::namespace::NamespaceParameters,
    },
    request_metadata::RequestMetadata,
    server::require_warehouse_id,
    service::{
        CachePolicy, CatalogGenericTableOps, CatalogStore, Result, SecretStore, State, Transaction,
        authz::{
            ActionOnGenericTable, AuthZGenericTableOps, Authorizer, AuthzNamespaceOps,
            CatalogGenericTableAction, CatalogNamespaceAction, ListAllowedEntitiesResponse,
        },
        events::{
            APIEventContext, AuthorizationFailureSource,
            context::{ResolvedNamespace, UserProvidedNamespace},
        },
    },
};

pub(super) async fn list_generic_tables<C: CatalogStore, A: Authorizer + Clone, S: SecretStore>(
    parameters: NamespaceParameters,
    query: ListGenericTablesQuery,
    state: ApiContext<State<A, C, S>>,
    request_metadata: RequestMetadata,
) -> Result<ListGenericTablesResponse> {
    let NamespaceParameters { namespace, prefix } = &parameters;
    let warehouse_id = require_warehouse_id(prefix.as_ref())?;
    let authorizer = &state.v1_state.authz;

    // ------------------- AUTHZ: namespace-level ListGenericTables -------------------
    let event_ctx = APIEventContext::for_namespace(
        Arc::new(request_metadata.clone()),
        state.v1_state.events.clone(),
        warehouse_id,
        namespace.clone(),
        CatalogNamespaceAction::ListGenericTables,
    );

    let (event_ctx, (warehouse, ns)) = event_ctx.emit_authz(
        authorizer
            .load_and_authorize_namespace_action::<C>(
                &request_metadata,
                UserProvidedNamespace::new(warehouse_id, namespace.clone()),
                CatalogNamespaceAction::ListGenericTables,
                CachePolicy::Use,
                state.v1_state.catalog.clone(),
            )
            .await,
    )?;

    let _event_ctx = event_ctx.resolve(ResolvedNamespace {
        warehouse: warehouse.clone(),
        namespace: ns.namespace.clone(),
    });

    let namespace_id = ns.namespace.namespace_id();

    let mut t = C::Transaction::begin_read(state.v1_state.catalog).await?;
    let (entries, next_page_token) = C::list_generic_tables(
        warehouse_id,
        namespace_id,
        namespace,
        query.page_size,
        query.page_token.as_deref(),
        t.transaction(),
    )
    .await?;
    t.commit().await?;

    // ------------------- AUTHZ: per-entry IncludeInList filtering -------------------
    let can_list_everything = authorizer
        .is_allowed_namespace_action(
            &request_metadata,
            None,
            &warehouse,
            &ns.parents,
            &ns.namespace,
            CatalogNamespaceAction::ListEverything,
        )
        .await
        .map_err(AuthorizationFailureSource::into_error_model)?
        .into_inner();

    // Get allowed generic table IDs if not ListEverything
    let allowed_response = if can_list_everything {
        ListAllowedEntitiesResponse::All
    } else {
        authorizer
            .list_allowed_generic_tables(&request_metadata, warehouse_id)
            .await?
    };

    // Filter based on allowed IDs, with fallback to legacy behavior
    let masks: Vec<bool> = match &allowed_response {
        ListAllowedEntitiesResponse::All => vec![true; entries.len()],
        ListAllowedEntitiesResponse::Ids(allowed_ids) => entries
            .iter()
            .map(|entry| allowed_ids.contains(&entry.generic_table_id))
            .collect(),
        ListAllowedEntitiesResponse::NotImplemented => {
            // Fallback to legacy per-item authorization check
            let actions: Vec<_> = entries
                .iter()
                .map(|entry| {
                    (
                        &ns.namespace,
                        ActionOnGenericTable {
                            info: entry,
                            action: CatalogGenericTableAction::IncludeInList,
                            user: None,
                            is_delegated_execution: false,
                        },
                    )
                })
                .collect();

            let parents: HashMap<_, _> = ns
                .parents
                .iter()
                .map(|n| (n.namespace_id(), n.clone()))
                .collect();
            authorizer
                .are_allowed_generic_table_actions_vec(
                    &request_metadata,
                    &warehouse,
                    &parents,
                    &actions,
                )
                .await
                .map_err(AuthorizationFailureSource::into_error_model)?
                .into_allowed()
        }
    };

    let identifiers = entries
        .into_iter()
        .zip(masks)
        .filter(|(_, allowed)| *allowed)
        .map(|(entry, _)| GenericTableIdentifier {
            namespace: namespace.clone().inner(),
            name: entry.name,
            format: Some(entry.format),
            id: Some(entry.generic_table_id),
        })
        .collect();

    Ok(ListGenericTablesResponse {
        identifiers,
        next_page_token,
    })
}
