// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::collections::BTreeMap;
use std::net::Ipv6Addr;

use anyhow::Context;
use clap::Subcommand;
use uuid::Uuid;

use dpd_client::Client;

#[derive(Debug, Subcommand)]
/// Manage routers
pub enum Router {
    /// List all routers and their endpoints
    #[clap(visible_alias = "ls")]
    List,
    /// Show a router's endpoint
    Get {
        /// Router uuid
        router_id: Uuid,
    },
    /// Create a router
    Create {
        /// Router uuid
        router_id: Uuid,
        /// Endpoint address
        #[clap(long)]
        endpoint: Ipv6Addr,
    },
    /// Delete a router along with its endpoint and routes
    Delete {
        /// Router uuid
        router_id: Uuid,
    },
}

pub async fn router_cmd(client: &Client, cmd: Router) -> anyhow::Result<()> {
    match cmd {
        Router::List => {
            let routers = client
                .router_list()
                .await
                .context("failed to list routers")?
                .into_inner();
            let routers: BTreeMap<String, Ipv6Addr> =
                routers.into_iter().collect();
            for (router_id, endpoint) in routers {
                println!("{router_id} {endpoint}");
            }
            Ok(())
        }
        Router::Get { router_id } => {
            let endpoint = client
                .router_get(&router_id)
                .await
                .context("failed to get router")?
                .into_inner();
            println!("{endpoint}");
            Ok(())
        }
        Router::Create { router_id, endpoint } => client
            .router_create(&router_id, &endpoint)
            .await
            .context("failed to create router")
            .map(|_| ()),
        Router::Delete { router_id } => client
            .router_delete(&router_id)
            .await
            .context("failed to delete router")
            .map(|_| ()),
    }
}
