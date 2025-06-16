pub mod cache;
pub mod prefetch;

pub use cache::{AdvancedCache, MultiTierCache, EvictionPolicy, CacheStats};
pub use prefetch::{PredictivePrefetcher, PrefetchStrategy, AccessPattern, PrefetchRequest};