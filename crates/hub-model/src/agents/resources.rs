use serde::{Deserialize, Serialize};

/// A resource figure outside its allowed range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResourceError {
    /// CPU, memory, disk or parallel runs is zero or above its bound.
    #[error("resource request is outside its allowed range")]
    OutOfRange,
}

/// What one instance of an agent asks of a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceRequest {
    /// CPU in thousandths of a core while a lease is active.
    pub cpu_milli: u32,
    /// Memory in MiB while a lease is active.
    pub mem_mib: u32,
    /// Disk reserved for the instance volume, in MiB.
    pub disk_mib: u32,
    /// Runs the instance may execute at once.
    pub max_parallel_runs: u32,
}

impl ResourceRequest {
    /// Upper bound of one request: 64 cores, 256 GiB memory, 4 TiB disk, 64 runs.
    pub const MAX: ResourceRequest = ResourceRequest {
        cpu_milli: 64_000,
        mem_mib: 256 * 1024,
        disk_mib: 4 * 1024 * 1024,
        max_parallel_runs: 64,
    };

    /// Checks that every figure is positive and within [`ResourceRequest::MAX`].
    pub fn validate(&self) -> Result<(), ResourceError> {
        let within = |value: u32, max: u32| (1..=max).contains(&value);
        if within(self.cpu_milli, Self::MAX.cpu_milli)
            && within(self.mem_mib, Self::MAX.mem_mib)
            && within(self.disk_mib, Self::MAX.disk_mib)
            && within(self.max_parallel_runs, Self::MAX.max_parallel_runs)
        {
            Ok(())
        } else {
            Err(ResourceError::OutOfRange)
        }
    }
}

/// Quota limits of one scope or of one member inside it. `None` means no limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ScopeLimits {
    /// Seats (instances) that may exist.
    pub max_instances: Option<u32>,
    /// Leases that may be active at once.
    pub max_active_leases: Option<u32>,
    /// CPU, in thousandths of a core, leased at once.
    pub max_cpu_milli: Option<u64>,
    /// Memory in MiB leased at once.
    pub max_mem_mib: Option<u64>,
    /// Disk in MiB reserved by instances.
    pub max_disk_mib: Option<u64>,
    /// Spend per month in millionths of the billing unit.
    pub monthly_spend_micros: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ResourceRequest {
        ResourceRequest {
            cpu_milli: 1000,
            mem_mib: 512,
            disk_mib: 1024,
            max_parallel_runs: 2,
        }
    }

    #[test]
    fn a_reasonable_request_is_valid() {
        assert_eq!(request().validate(), Ok(()));
        assert_eq!(ResourceRequest::MAX.validate(), Ok(()));
    }

    #[test]
    fn zero_and_oversized_figures_are_refused() {
        for broken in [
            ResourceRequest {
                cpu_milli: 0,
                ..request()
            },
            ResourceRequest {
                mem_mib: 0,
                ..request()
            },
            ResourceRequest {
                disk_mib: ResourceRequest::MAX.disk_mib + 1,
                ..request()
            },
            ResourceRequest {
                max_parallel_runs: 65,
                ..request()
            },
        ] {
            assert_eq!(broken.validate(), Err(ResourceError::OutOfRange));
        }
    }
}
