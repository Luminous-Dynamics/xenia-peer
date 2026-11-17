use std::collections::{BTreeMap, BTreeSet};
use std::hint::black_box;
use std::time::Instant;

use xenia_access_model::{
    AccessRequest, AuthorityFrontier, AuthorityMode, AuthorityState, Delegation, Resource, Right,
};

fn fixture(depth: u16) -> (AuthorityState, String, AccessRequest) {
    let resource = Resource { domain: "benchmark-domain".into(), id: "host-001".into() };
    let rights: BTreeSet<_> = [Right::View].into_iter().collect();
    let mut grants = BTreeMap::new();
    let mut parent: Option<String> = None;
    let mut issuer = "principal".to_owned();
    let mut leaf = String::new();

    for level in 0..=depth {
        let id = format!("grant-{level}");
        let holder = format!("agent-{level}");
        let remaining_depth = depth - level;
        let grant = Delegation {
            id: id.clone(),
            principal: "principal".into(),
            issuer: issuer.clone(),
            holder: holder.clone(),
            resource: resource.clone(),
            rights: rights.clone(),
            purpose: "benchmark".into(),
            mode: AuthorityMode::Execute,
            not_before_ms: 0,
            expires_at_ms: u64::MAX,
            authority_epoch: 1,
            parent: parent.clone(),
            may_subdelegate: remaining_depth > 0,
            remaining_depth,
        };
        grants.insert(id.clone(), grant);
        parent = Some(id.clone());
        issuer = holder;
        leaf = id;
    }

    let mut epochs = BTreeMap::new();
    epochs.insert("benchmark-domain".into(), 1);
    (
        AuthorityState { grants, revoked: BTreeSet::new(), epochs, complete: true },
        leaf,
        AccessRequest {
            resource,
            right: Right::View,
            purpose: "benchmark".into(),
            requires_execution: true,
        },
    )
}

fn percentile(sorted: &[u128], percentile: usize) -> u128 {
    let index = ((sorted.len() - 1) * percentile).div_ceil(100);
    sorted[index]
}

fn report(mode: &str, depth: u16, mut evaluate: impl FnMut() -> impl Sized) {
    const SAMPLES: usize = 20_000;
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        black_box(evaluate());
        samples.push(start.elapsed().as_nanos());
    }
    samples.sort_unstable();
    println!(
        "{mode},{depth},{SAMPLES},{},{},{},{}",
        percentile(&samples, 50),
        percentile(&samples, 95),
        percentile(&samples, 99),
        samples[samples.len() - 1],
    );
}

fn main() {
    println!("mode,lineage_depth,samples,p50_ns,p95_ns,p99_ns,max_ns");
    for depth in [0_u16, 1, 4, 8, 16] {
        let (state, id, request) = fixture(depth);
        let observed = AuthorityFrontier { namespace: "benchmark-domain".into(), revision: 7 };
        let minimum = AuthorityFrontier { namespace: "benchmark-domain".into(), revision: 7 };
        report("lineage_only", depth, || {
            state.evaluate_request(black_box(&id), black_box(&request), 10)
        });
        report("frontier_plus_lineage", depth, || {
            state.evaluate_request_at_frontier(
                black_box(&id),
                black_box(&request),
                10,
                black_box(&observed),
                black_box(&minimum),
            )
        });
    }
}
