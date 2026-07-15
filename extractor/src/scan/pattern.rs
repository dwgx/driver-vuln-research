use crate::scan::aes::{has_high_entropy, is_valid_aes128_schedule};

/// Result of finding an AES-128 key schedule in a memory page.
#[derive(Debug, Clone)]
pub struct AesKeyResult {
    /// Byte offset within the page where the key starts.
    pub offset: usize,
    /// The 16-byte AES-128 key.
    pub key: [u8; 16],
    /// Confidence score (0.0 to 1.0) based on entropy analysis.
    pub confidence: f64,
}

/// Scan a memory page for valid AES-128 key schedules.
///
/// Slides a 16-byte window across the page data. For each position where
/// at least 176 bytes remain, expands the 16 bytes as if they were an AES key
/// and checks whether the following 160 bytes match the expected schedule.
pub fn scan_page_for_aes_schedule(page_data: &[u8]) -> Vec<AesKeyResult> {
    let mut results = Vec::new();

    if page_data.len() < 176 {
        return results;
    }

    let end = page_data.len() - 176;

    for offset in 0..=end {
        let candidate_key: &[u8; 16] = match page_data[offset..offset + 16].try_into() {
            Ok(k) => k,
            Err(_) => continue,
        };

        // Skip all-zero keys (common in uninitialized memory)
        if candidate_key.iter().all(|&b| b == 0) {
            continue;
        }

        let candidate_schedule: &[u8; 176] = match page_data[offset..offset + 176].try_into() {
            Ok(s) => s,
            Err(_) => continue,
        };

        if is_valid_aes128_schedule(candidate_schedule) {
            let confidence = compute_key_confidence(candidate_key);
            results.push(AesKeyResult {
                offset,
                key: *candidate_key,
                confidence,
            });
        }
    }

    results
}

/// Scan a memory page for all 16-byte sequences with Shannon entropy above
/// the given threshold (default 3.5 bits/byte).
///
/// Returns the byte offsets where high-entropy 16-byte blocks begin.
pub fn scan_page_for_high_entropy_16(page_data: &[u8]) -> Vec<usize> {
    const BLOCK_SIZE: usize = 16;
    const THRESHOLD: f64 = 3.5;

    let mut offsets = Vec::new();

    if page_data.len() < BLOCK_SIZE {
        return offsets;
    }

    let end = page_data.len() - BLOCK_SIZE;

    for offset in (0..=end).step_by(BLOCK_SIZE) {
        let block = &page_data[offset..offset + BLOCK_SIZE];
        if has_high_entropy(block, THRESHOLD) {
            offsets.push(offset);
        }
    }

    offsets
}

/// Compute a confidence score for a candidate AES key based on entropy
/// and byte distribution characteristics.
fn compute_key_confidence(key: &[u8; 16]) -> f64 {
    let mut counts = [0u32; 256];
    for &b in key.iter() {
        counts[b as usize] += 1;
    }

    let len = 16.0f64;

    // Shannon entropy
    let entropy: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum();

    // Max entropy for 16 bytes is 4.0 (all unique)
    let max_entropy = 4.0;
    let entropy_score = (entropy / max_entropy).min(1.0);

    // Count unique byte values
    let unique_count = counts.iter().filter(|&&c| c > 0).count() as f64;
    let uniqueness_score = (unique_count / 16.0).min(1.0);

    // Weighted combination
    0.7 * entropy_score + 0.3 * uniqueness_score
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::aes::aes128_key_expand;

    #[test]
    fn test_scan_finds_embedded_schedule() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let schedule = aes128_key_expand(&key);

        // Embed the schedule at offset 64 within a larger buffer
        let mut page = vec![0xAA_u8; 512];
        page[64..64 + 176].copy_from_slice(&schedule);

        let results = scan_page_for_aes_schedule(&page);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].offset, 64);
        assert_eq!(results[0].key, key);
        assert!(results[0].confidence > 0.5);
    }

    #[test]
    fn test_scan_no_false_positives_on_zeros() {
        let page = vec![0u8; 4096];
        let results = scan_page_for_aes_schedule(&page);
        assert!(results.is_empty());
    }

    #[test]
    fn test_high_entropy_scan() {
        // Create a page with one high-entropy block at offset 0
        let mut page = vec![0u8; 256];
        for i in 0..16 {
            page[i] = (i as u8).wrapping_mul(17).wrapping_add(53);
        }

        let offsets = scan_page_for_high_entropy_16(&page);
        assert!(offsets.contains(&0));
        // Zeros should not appear
        assert!(!offsets.contains(&16));
    }

    #[test]
    fn test_page_too_small() {
        let page = vec![0xAB_u8; 100];
        let results = scan_page_for_aes_schedule(&page);
        assert!(results.is_empty());
    }
}
