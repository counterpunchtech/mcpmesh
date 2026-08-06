//! Ingress filtering for address-lookup results (#203).
//!
//! Every other fix for #203 filtered an address blob at a CALL SITE — the pairing invite, the
//! attestation offer, a gossip ticket, a blob ticket. Review established that this cannot bound the
//! problem: `Endpoint::connect` and `blobs.fetch` resolve a peer **by id**, which triggers address
//! lookup, and on the default n0 preset that means pkarr and DNS. **A pkarr record is self-signed by
//! the endpoint key**, so anyone who generates a key can publish an arbitrary address list under it
//! and have every entry inserted into iroh's path set — `insert_multiple(addrs, Source::AddressLookup)`
//! — with no hygiene whatever. iroh has no destination filter of its own: its `AddrFilter` is
//! publish-side only, by design.
//!
//! So this is the layer that actually bounds it. [`Hygienic`] wraps an [`AddressLookup`] and strips
//! every resolved address that can never be a unicast QUIC peer, using the same
//! [`dialable_only`](crate::daemon::dial::dialable_only) predicate the dial paths use — one rule,
//! applied at ingress instead of at each of four call sites.
//!
//! **It wraps RESOLVERS, not the publisher.** `publish` carries our own addresses outward and is
//! already governed by `AddrFilter`; filtering it here would be filtering ourselves.
//!
//! **What it does NOT do**, so the gap is not mistaken for closed: relay URLs pass, exactly as they
//! do at every other site. iroh opens an outbound TLS connection to any relay URL it is handed, and
//! deciding which relay URLs are acceptable needs a provenance model rather than a destination
//! predicate — #203's remaining item.

use iroh::address_lookup::{
    AddressLookup, AddressLookupBuilder, AddressLookupBuilderError, EndpointData, EndpointInfo,
    Item,
};

/// Wrap an address-lookup BUILDER so the service it builds filters what it resolves.
#[derive(Debug)]
pub(crate) struct Hygienic<B>(pub(crate) B);

impl<B: AddressLookupBuilder> AddressLookupBuilder for Hygienic<B> {
    fn into_address_lookup(
        self,
        endpoint: &iroh::Endpoint,
    ) -> Result<impl AddressLookup, AddressLookupBuilderError> {
        Ok(HygienicLookup(self.0.into_address_lookup(endpoint)?))
    }
}

/// The built service: delegates everything, filters what `resolve` yields.
#[derive(Debug)]
struct HygienicLookup<L>(L);

impl<L: AddressLookup> AddressLookup for HygienicLookup<L> {
    fn publish(&self, data: &EndpointData) {
        // Outbound: our own addresses, already governed by `AddrFilter`. Untouched.
        self.0.publish(data);
    }

    fn resolve(
        &self,
        endpoint_id: iroh::EndpointId,
    ) -> Option<n0_future::boxed::BoxStream<Result<Item, iroh::address_lookup::Error>>> {
        let inner = self.0.resolve(endpoint_id)?;
        Some(Box::pin(n0_future::StreamExt::map(inner, |r| {
            r.map(filter_item)
        })))
    }
}

/// Strip a resolved item of every address that can never be a unicast QUIC peer.
///
/// Rebuilt rather than mutated: `EndpointInfo` exposes no way to remove a single address, and
/// `clear_ip_addrs` + re-add would drop the relay entries this deliberately preserves.
///
/// `user_data` is carried across — it is the endpoint's own annotation and nothing to do with
/// reachability, and silently dropping it would change behaviour for anyone using it.
pub(crate) fn filter_item(item: Item) -> Item {
    let info = item.endpoint_info().clone();
    let id = info.endpoint_id;
    let user_data = info.data.user_data().cloned();

    let kept = crate::daemon::dial::dialable_only(iroh::EndpointAddr::from(info));
    let mut data = EndpointData::from(kept);
    data.set_user_data(user_data);

    Item::new(
        EndpointInfo::from_parts(id, data),
        item.provenance(),
        item.last_updated(),
    )
}

#[cfg(test)]
mod tests {
    use super::filter_item;
    use iroh::address_lookup::{EndpointInfo, Item};

    fn item_of(addrs: Vec<iroh::TransportAddr>) -> (iroh::EndpointId, Item) {
        let id = iroh::SecretKey::from_bytes(&[77u8; 32]).public();
        let info = EndpointInfo::from(iroh::EndpointAddr::from_parts(id, addrs));
        (id, Item::new(info, "test", Some(42)))
    }

    /// A stand-in service that yields one hostile item, so `resolve` itself can be driven.
    #[derive(Debug)]
    struct Fake(Vec<iroh::TransportAddr>);

    impl iroh::address_lookup::AddressLookup for Fake {
        fn resolve(
            &self,
            endpoint_id: iroh::EndpointId,
        ) -> Option<n0_future::boxed::BoxStream<Result<Item, iroh::address_lookup::Error>>>
        {
            let info =
                EndpointInfo::from(iroh::EndpointAddr::from_parts(endpoint_id, self.0.clone()));
            let item = Item::new(info, "fake", None);
            Some(Box::pin(n0_future::stream::iter(vec![Ok(item)])))
        }
    }

    /// #203, AT THE CALL SITE: the wrapper's `resolve` actually applies the filter.
    ///
    /// `filter_item` passing says nothing about whether `resolve` calls it — and it did not, in the
    /// first cut: replacing the whole body with `self.0.resolve(endpoint_id)` left both unit tests
    /// green. Fourth occurrence of that failure in this session, so the stream is driven here
    /// rather than the helper asserted.
    #[tokio::test]
    async fn the_wrapper_filters_what_it_yields() {
        use n0_future::StreamExt as _;

        let inner = Fake(vec![
            iroh::TransportAddr::Ip("0.0.0.0:53".parse().unwrap()),
            iroh::TransportAddr::Ip("224.0.0.1:1900".parse().unwrap()),
            iroh::TransportAddr::Ip("192.168.4.4:4433".parse().unwrap()),
        ]);
        let wrapped = super::HygienicLookup(inner);
        let id = iroh::SecretKey::from_bytes(&[78u8; 32]).public();

        let mut stream = iroh::address_lookup::AddressLookup::resolve(&wrapped, id)
            .expect("the wrapper delegates and yields a stream");
        let first = stream.next().await.expect("one item").expect("ok");
        let addr = iroh::EndpointAddr::from(first.endpoint_info().clone());
        assert_eq!(
            addr.addrs.len(),
            1,
            "the wrapper must filter what it yields, not merely delegate: {addr:?}"
        );
        assert_eq!(addr.id, id);
    }

    /// #203: a RESOLVED address that can never be a unicast QUIC peer never reaches the path set.
    ///
    /// This is the layer the four call-site filters could not reach. `connect` and `blobs.fetch`
    /// resolve by ID, address lookup runs regardless of what any blob carried, and a pkarr record
    /// is self-signed by the endpoint key — so without this, anyone who generates a key publishes
    /// an arbitrary destination list and iroh dials all of it.
    #[test]
    fn a_resolved_address_that_cannot_be_a_peer_is_stripped() {
        let (id, item) = item_of(vec![
            iroh::TransportAddr::Ip("0.0.0.0:53".parse().unwrap()),
            iroh::TransportAddr::Ip("224.0.0.1:1900".parse().unwrap()),
            iroh::TransportAddr::Ip("255.255.255.255:80".parse().unwrap()),
            // The IPv4-MAPPED forms too — `Ipv6Addr::is_multicast` does not see through them, and
            // iroh canonicalizes on ingest, so an unfiltered mapped address becomes real multicast.
            iroh::TransportAddr::Ip("[::ffff:224.0.0.1]:1900".parse().unwrap()),
            iroh::TransportAddr::Ip("192.168.4.4:4433".parse().unwrap()),
        ]);

        let out = filter_item(item);
        let addr = iroh::EndpointAddr::from(out.endpoint_info().clone());
        assert_eq!(
            addr.addrs.len(),
            1,
            "only the dialable address survives resolution: {addr:?}"
        );
        assert_eq!(
            addr.id, id,
            "and the item still names the endpoint it resolved"
        );
    }

    /// Legitimate resolution is untouched, and the item's metadata survives.
    ///
    /// The failure mode of an ingress filter is not "lets something through" — it is breaking
    /// discovery for everyone. A relay URL in particular MUST survive: it is how a peer behind a
    /// NAT is reached, and dropping it here would silently disable relay-mediated connectivity for
    /// every peer resolved through pkarr or DNS.
    #[test]
    fn legitimate_resolution_and_metadata_survive() {
        let (id, item) = item_of(vec![
            iroh::TransportAddr::Relay("https://relay.example".parse().unwrap()),
            iroh::TransportAddr::Ip("192.168.1.5:4433".parse().unwrap()),
            iroh::TransportAddr::Ip("[2001:db8::1]:4433".parse().unwrap()),
            iroh::TransportAddr::Ip("[fe80::1]:4433".parse().unwrap()),
            iroh::TransportAddr::Ip("127.0.0.1:4433".parse().unwrap()),
        ]);

        let out = filter_item(item);
        assert_eq!(
            out.provenance(),
            "test",
            "the source label must survive — iroh uses it to attribute paths"
        );
        assert_eq!(out.last_updated(), Some(42));
        let addr = iroh::EndpointAddr::from(out.endpoint_info().clone());
        assert_eq!(addr.id, id);
        assert_eq!(
            addr.addrs.len(),
            5,
            "every legitimate class survives, the relay URL above all: {addr:?}"
        );
        assert!(
            addr.addrs
                .iter()
                .any(|a| matches!(a, iroh::TransportAddr::Relay(_))),
            "dropping the relay would disable relay-mediated connectivity for every resolved \
             peer — the failure mode of an ingress filter is breaking discovery, not leaking: \
             {addr:?}"
        );
    }
}
