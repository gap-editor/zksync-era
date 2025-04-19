use std::{str::FromStr, sync::Arc, time::Duration}; // <-- Added time::Duration

use rust_eigenda_client::{
    client::BlobProvider,
    config::{PrivateKey, SrsPointsSource},
    EigenClient,
};
use subxt_signer::ExposeSecret;
use tokio::time::timeout; // <-- Added tokio::time::timeout
use url::Url;
use zksync_config::{
    configs::da_client::eigen::{EigenSecrets, PointsSource},
    EigenConfig,
};
use zksync_da_client::{
    types::{ClientType, DAError, DispatchResponse, FinalityResponse, InclusionData},
    DataAvailabilityClient,
};

use crate::utils::to_retriable_da_error;

// Define reasonable defaults for polling
const FINALITY_POLL_INTERVAL: Duration = Duration::from_secs(5);
// Consider making this configurable if needed
const FINALITY_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes

// We can't implement DataAvailabilityClient for an outside struct, so it is needed to defined this intermediate struct
#[derive(Debug, Clone)]
pub struct EigenDAClient {
    client: EigenClient,
    // Store the wait_for_finalization flag if needed, or rely on polling which works either way
    // wait_for_finalization_in_dispatch: bool, // Optional optimization
}

impl EigenDAClient {
    pub async fn new(
        config: EigenConfig,
        secrets: EigenSecrets,
        blob_provider: Arc<dyn BlobProvider>,
    ) -> anyhow::Result<Self> {
        let url = Url::from_str(
            config
                .eigenda_eth_rpc
                .ok_or(anyhow::anyhow!("Eigenda eth rpc url is not set"))?
                .expose_str(),
        )
        .map_err(|_| anyhow::anyhow!("Invalid eth rpc url"))?;
        let eth_rpc_url = rust_eigenda_client::config::SecretUrl::new(url);

        let srs_points_source = match config.points_source {
            PointsSource::Path(path) => SrsPointsSource::Path(path),
            PointsSource::Url(url) => SrsPointsSource::Url(url),
        };

        // Keep track if dispatch_blob itself waits for finality
        let wait_for_finalization_in_dispatch = config.wait_for_finalization;

        let eigen_config = rust_eigenda_client::config::EigenConfig::new(
            config.disperser_rpc,
            eth_rpc_url,
            config.settlement_layer_confirmation_depth,
            config.eigenda_svc_manager_address,
            wait_for_finalization_in_dispatch, // Use the flag here
            config.authenticated,
            srs_points_source,
            config.custom_quorum_numbers,
        )?;
        let private_key = PrivateKey::from_str(secrets.private_key.0.expose_secret())
            .map_err(|e| anyhow::anyhow!("Failed to parse private key: {}", e))?;
        let eigen_secrets = rust_eigenda_client::config::EigenSecrets { private_key };
        let client = EigenClient::new(eigen_config, eigen_secrets, blob_provider)
            .await
            .map_err(|e| anyhow::anyhow!("Eigen client Error: {:?}", e))?;
        Ok(Self {
            client,
            // wait_for_finalization_in_dispatch, // Store if optimizing
        })
    }
}

#[async_trait::async_trait]
impl DataAvailabilityClient for EigenDAClient {
    async fn dispatch_blob(
        &self,
        _: u32, // batch number
        data: Vec<u8>,
    ) -> Result<DispatchResponse, DAError> {
        // dispatch_blob might wait internally depending on the config flag `wait_for_finalization`
        // It returns the blob_id regardless.
        let blob_id = self
            .client
            .dispatch_blob(data)
            .await
            .map_err(to_retriable_da_error)?;

        Ok(DispatchResponse::from(blob_id))
    }

    async fn ensure_finality(
        &self,
        dispatch_request_id: String, // This is the blob_id returned by dispatch_blob
    ) -> Result<Option<FinalityResponse>, DAError> {
        let blob_id = dispatch_request_id; // Clarity: the request ID is the blob ID

        // Optimization: If dispatch_blob already waited, we can potentially return faster.
        // However, polling `get_inclusion_data` once is a safe way to confirm,
        // and it handles the case where `wait_for_finalization` was false.
        // Let's implement the robust polling approach which works in both scenarios.

        let check_finality = async {
            loop {
                tracing::debug!("Checking finality for blob_id: {}", blob_id);
                match self.get_inclusion_data(&blob_id).await {
                    Ok(Some(_)) => {
                        // Inclusion data is available, meaning it's finalized
                        tracing::info!("Blob {} confirmed as final.", blob_id);
                        return Ok(Some(FinalityResponse {
                            blob_id: blob_id.clone(),
                        }));
                    }
                    Ok(None) => {
                        // Not final yet, wait and retry
                        tracing::debug!(
                            "Blob {} not final yet, retrying in {:?}...",
                            blob_id,
                            FINALITY_POLL_INTERVAL
                        );
                        tokio::time::sleep(FINALITY_POLL_INTERVAL).await;
                    }
                    Err(e) => {
                        // Propagate errors, allowing retries if applicable
                        tracing::warn!(
                            "Error checking finality for blob {}: {:?}. Retrying might occur.",
                            blob_id,
                            e
                        );
                        // We return the error here; the caller (or timeout wrapper) decides next steps.
                        // If the error is retriable (based on to_retriable_da_error in get_inclusion_data),
                        // the caller might retry the ensure_finality call itself.
                        // If it's not retriable, it propagates up.
                        // We could also add specific retry logic *within* this loop for certain errors
                        // if desired, but relying on `get_inclusion_data`'s error mapping is simpler.
                        return Err(e);
                    }
                }
            }
        };

        // Wrap the polling loop in a timeout
        match timeout(FINALITY_TIMEOUT, check_finality).await {
            Ok(Ok(response)) => Ok(response), // Polling succeeded within timeout
            Ok(Err(e)) => Err(e),             // Polling returned an error within timeout
            Err(_) => {
                // Timeout elapsed
                tracing::error!(
                    "Timeout waiting for finality of blob {} after {:?}",
                    blob_id,
                    FINALITY_TIMEOUT
                );
                Err(DAError::Timeout(format!(
                    "Timeout waiting for finality of blob {}",
                    blob_id
                )))
            }
        }
    }

    async fn get_inclusion_data(&self, blob_id: &str) -> Result<Option<InclusionData>, DAError> {
        let inclusion_data = self
            .client
            .get_inclusion_data(blob_id)
            .await
            .map_err(to_retriable_da_error)?; // Map Eigen client error to DAError

        Ok(inclusion_data.map(|data| InclusionData { data })) // Map Option<Vec<u8>> to Option<InclusionData>
    }

    fn clone_boxed(&self) -> Box<dyn DataAvailabilityClient> {
        Box::new(self.clone())
    }

    fn blob_size_limit(&self) -> Option<usize> {
        self.client.blob_size_limit()
    }

    fn client_type(&self) -> ClientType {
        ClientType::Eigen
    }

    async fn balance(&self) -> Result<u64, DAError> {
        Ok(0) // TODO fetch from API when payments are enabled in Eigen (PE-305)
    }
}

// Make sure you have this utility function defined somewhere accessible
// Example stub:
// mod utils {
//     use zksync_da_client::types::DAError;
//     pub fn to_retriable_da_error<E: std::fmt::Debug>(err: E) -> DAError {
//         // Implement actual logic to classify errors as retriable or permanent
//         tracing::error!("EigenDA client error: {:?}", err);
//         DAError::Network(err.to_string().into()) // Example: Treat as generic network error
//         // Or DAError::Permanent(err.to_string().into())
//         // Or DAError::Auth(err.to_string().into()) etc.
//     }
// }

// Assume crate::utils exists and has the function
mod utils {
    use zksync_da_client::types::DAError;
    // Placeholder - replace with your actual implementation
    pub fn to_retriable_da_error<E: std::fmt::Debug>(err: E) -> DAError {
        let err_string = format!("{:?}", err);
        // Add specific error matching here if needed to classify errors
        // For now, treat most as potentially retriable Network errors
        tracing::warn!("Mapping Eigen client error to DAError: {}", err_string);
        DAError::Network(err_string.into())
    }
}
