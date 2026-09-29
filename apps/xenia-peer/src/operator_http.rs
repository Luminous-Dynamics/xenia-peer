
    // Fast reject only. The coherent-snapshot path below rechecks the effective
    // revocation state while the same authority read barrier remains held.
    if authority.revocations.is_revoked(&authorized.operator_id) {
        tracing::warn!(operator = %authorized.operator_id, "Symthaea authority issuance refused: operator revoked");
        return Err((StatusCode::FORBIDDEN, "Symthaea authority issuance refused".to_string()));
    }

    let binding_digest = symthaea_authorization_binding_digest(&request);
    match issuance.journal.reserve(authorized.request_nonce, binding_digest) {
        Ok(ReserveOutcome::AlreadyIssued { receipt }) => {
            return Ok(symthaea_receipt_response(receipt));
        }
        Ok(ReserveOutcome::DeliveryUnknown) => {
            return Err((
                StatusCode::CONFLICT,
                "issuance outcome is delivery-unknown; reuse the exact request nonce only after operator recovery inspects the journal"
                    .to_string(),
            ));
        }
        Ok(ReserveOutcome::Aborted) => {
            return Err((
                StatusCode::CONFLICT,
                "issuance request nonce is permanently aborted".to_string(),
            ));
        }
        Ok(ReserveOutcome::Reserved) => {}
        Err(error) => {
            tracing::error!(?error, "failed to reserve Symthaea issuance nonce");
            return Err((StatusCode::SERVICE_UNAVAILABLE, "Symthaea issuance unavailable".to_string()));
        }
    }

    let operator_id = authorized.operator_id.clone();
    let authority_scope = authorized.authority_scope.clone();
    let symthaea_receipt_id = authorized.symthaea_receipt_id;
    let symthaea_receipt_digest_sha256 = authorized.symthaea_receipt_digest_sha256;
    let request_nonce = authorized.request_nonce;
    let result = authority.with_coherent_snapshot(&operator_id, |snapshot| {
        // The token was checked before journal reservation. Re-check its
        // expiry at the coherent-snapshot boundary so a long-running
        // snapshot/signing operation cannot turn an already-expired operator
        // session into a fresh portable authority receipt.
        let authorized_at_unix_s = unix_now_secs();
        if authorized_at_unix_s > request.token.token.expires_at {
            return Err("operator token expired before coherent issuance snapshot".to_string());
        }
        if authority.revocations.is_revoked(&operator_id) {
            return Err("operator was revoked before coherent issuance snapshot commit".to_string());
        }
        let snapshot_key_lineage = symthaea_key_lineage_commitment_v1(
            &snapshot.value().operator().ed25519_pubkey,
            &snapshot.value().operator().ml_dsa_65_pubkey,
        )
        .map_err(|error| format!("coherent operator key lineage is malformed: {error}"))?;
        if snapshot_key_lineage != authorized.authenticated_key_lineage_commitment {
            return Err(
                "operator key lineage changed after authentication; refusing issuance".to_string(),
            );
        }
        let request_for_issuer = DaemonSymthaeaAuthorizationRequestV1 {
            operator_id: operator_id.clone(),
            authority_scope,
            symthaea_receipt_id,
            symthaea_receipt_digest_sha256,
            request_nonce,
        };
        let daemon_certificate_commitment = daemon_certificate_commitment_sha256_v1(
            &state.daemon_certificate,
        )
        .ok_or_else(|| "daemon delegation certificate is structurally invalid".to_string())?;
        let signed = issue_symthaea_authorization_receipt_v1(
            &request_for_issuer,
            snapshot,
            authorized_at_unix_s,
            MAX_AUTHORIZATION_TTL_SECS_V1,
            daemon_certificate_commitment,
            issuance.verifier_artifact_commitment_sha256,
            &state.daemon_key,
            &state.daemon_ml_dsa,
        )
        .map_err(|error| error.to_string())?;
        if !signed.validate_structure() {
            return Err("issued Symthaea authorization receipt failed structural validation".to_string());
        }
        let receipt_bytes = serde_json::to_vec(&signed)
            .map_err(|error| format!("failed to serialize signed Symthaea receipt: {error}"))?;
        issuance
            .journal
            .record_issued(request_nonce, binding_digest, &receipt_bytes)
            .map_err(|error| format!("failed to durably retain signed Symthaea receipt: {error}"))?;
        Ok(receipt_bytes)
    });
