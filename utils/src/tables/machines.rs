//! Some constants for the Machines Table

use super::{Item, MapItem, PrimaryHashKey};
use crate::dynamodb::maps_mk2::*;

pub struct MachinesTable {
    pub table_name: &'static str,
    /// primary index
    pub id: PrimaryHashKey<S>,
    /// Some hardware stats. This field will be null if the user doesn't provide
    /// any data
    pub stats: MapItem<Stats>,
}

pub struct Stats {
    pub os_name: Item<S>,
    pub is_64_bit: Item<Bool>,
    pub users_language: Item<S>,
    pub display_language: Item<S>,
    pub num_logical_cores: Item<N>,
    pub num_physical_cores: Item<N>,
    pub cpu_freq_mhz: Item<N>,
    pub cpu_architecture: Item<S>,
    pub ram_mb: Item<N>,
    pub page_size: Item<N>,
    pub cpu_vendor: Item<S>,
    pub cpu_model: Item<S>,
    pub has_mmx: Item<Bool>,
    pub has_3d_now: Item<Bool>,
    pub has_fma3: Item<Bool>,
    pub has_fma4: Item<Bool>,
    pub has_sse: Item<Bool>,
    pub has_sse2: Item<Bool>,
    pub has_sse3: Item<Bool>,
    pub has_ssse3: Item<Bool>,
    pub has_sse41: Item<Bool>,
    pub has_sse42: Item<Bool>,
    pub has_avx: Item<Bool>,
    pub has_avx2: Item<Bool>,
    pub has_avx512f: Item<Bool>,
    pub has_avx512bw: Item<Bool>,
    pub has_avx512cd: Item<Bool>,
    pub has_avx512dq: Item<Bool>,
    pub has_avx512er: Item<Bool>,
    pub has_avx512ifma: Item<Bool>,
    pub has_avx512pf: Item<Bool>,
    pub has_avx512vbmi: Item<Bool>,
    pub has_avx512vl: Item<Bool>,
    pub has_avx512vpopcntdq: Item<Bool>,
    pub has_neon: Item<Bool>,
}

pub const MACHINES_TABLE: MachinesTable = MachinesTable {
    table_name: "MACHINES-wbjyZs9LFVNrQaLT9aI-wAh6N4q_HTnh_CPv0oKDvXeMozio40MSyXVl",
    id: PrimaryHashKey { item: Item::new("id") },
    stats: MapItem { 
        key: Item::new("stats"), 
        fields: Stats { 
            os_name: Item::new("os"), 
            is_64_bit: Item::new("64_bit"), 
            users_language: Item::new("user_lang"), 
            display_language: Item::new("display_lang"), 
            num_logical_cores: Item::new("logical_cores"), 
            num_physical_cores: Item::new("physical_cores"), 
            cpu_freq_mhz: Item::new("cpu_mhz"), 
            cpu_architecture: Item::new("cpu_arch"),
            ram_mb: Item::new("ram_mb"), 
            page_size: Item::new("page_size"), 
            cpu_vendor: Item::new("cpu_vendor"), 
            cpu_model: Item::new("cpu_model"), 
            has_mmx: Item::new("MMX"), 
            has_3d_now: Item::new("3DNow"), 
            has_fma3: Item::new("FMA3"), 
            has_fma4: Item::new("FMA4"), 
            has_sse: Item::new("SSE"), 
            has_sse2: Item::new("SSE2"), 
            has_sse3: Item::new("SSE3"), 
            has_ssse3: Item::new("SSSE3"), 
            has_sse41: Item::new("SSE41"), 
            has_sse42: Item::new("SSE42"), 
            has_avx: Item::new("AVX"), 
            has_avx2: Item::new("AVX2"), 
            has_avx512f: Item::new("AVX512F"), 
            has_avx512bw: Item::new("AVX512BW"), 
            has_avx512cd: Item::new("AVX512CD"), 
            has_avx512dq: Item::new("AVX512DQ"), 
            has_avx512er: Item::new("AVX512ER"), 
            has_avx512ifma: Item::new("AVX512IFMA"), 
            has_avx512pf: Item::new("AVX512PF"), 
            has_avx512vbmi: Item::new("AVX512VBMI"), 
            has_avx512vl: Item::new("AVX512VL"), 
            has_avx512vpopcntdq: Item::new("AVX512VPOPCNTDQ"), 
            has_neon: Item::new("NEON"), 
        } 
    }
};