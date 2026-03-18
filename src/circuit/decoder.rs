//! Schema-aware column decoder for witness building.
//!
//! Decodes a canonical row byte slice into a u64 field element for a named
//! column, given a `DatasetSchema`. This enables schema-aware witness
//! building rather than always reading the first 8 raw bytes.
//!
//! ## Encoding layout (from `database/encoding.rs`)
//!
//! Row bytes = [8-byte row_index LE] ++ [column bytes in schema order].
//! Each column:
//!   - If nullable: 1-byte null sentinel (0x00 = null, 0x01 = present)
//!   - Then fixed-width value in little-endian order.
//!
//! This decoder skips variable-width columns (Text, Bytes, Uuid) since
//! they cannot be directly represented as Goldilocks field elements.

use crate::database::schema::DatasetSchema;
use crate::types::ColumnType;

/// Decode the value of a named column from a canonical row byte slice.
/// Returns `None` if the column is not found, the offset exceeds row_bytes,
/// or the column is variable-width / not representable as u64.
pub fn decode_column_u64(row_bytes: &[u8], schema: &DatasetSchema, col_name: &str) -> Option<u64> {
    // Skip 8-byte row_index prefix
    let mut offset = 8usize;

    for col in &schema.columns {
        if offset > row_bytes.len() {
            return None;
        }

        let is_target = col.name == col_name;

        // Handle nullable sentinel
        if col.nullable {
            if offset >= row_bytes.len() {
                return None;
            }
            let sentinel = row_bytes[offset];
            offset += 1;
            if sentinel == 0x00 {
                // null value
                if is_target {
                    return Some(0); // null → 0
                }
                continue; // skip to next column
            }
            // 0x01 = present, value follows
        }

        // Get fixed width; skip variable-width columns for now
        let width = match col.col_type.fixed_byte_width() {
            Some(w) => w,
            None => {
                // Variable-width: try to read 4-byte length prefix + skip
                if is_target {
                    return None; // can't decode as u64
                }
                if offset + 4 > row_bytes.len() {
                    return None;
                }
                let mut len_buf = [0u8; 4];
                len_buf.copy_from_slice(&row_bytes[offset..offset + 4]);
                let text_len = u32::from_le_bytes(len_buf) as usize;
                offset += 4 + text_len;
                continue;
            }
        };

        if is_target {
            if offset + width > row_bytes.len() {
                return None;
            }
            return Some(read_le_u64(
                &row_bytes[offset..offset + width],
                &col.col_type,
            ));
        }

        offset += width;
    }

    None
}

/// Extract all values for all columns in schema order, as u64 field elements.
/// Variable-width columns yield 0.
pub fn extract_column_values(row_bytes: &[u8], schema: &DatasetSchema) -> Vec<(String, u64)> {
    let mut result = Vec::with_capacity(schema.columns.len());
    let mut offset = 8usize; // skip row_index prefix

    for col in &schema.columns {
        if offset > row_bytes.len() {
            result.push((col.name.clone(), 0));
            continue;
        }

        let mut is_null = false;
        if col.nullable {
            if offset >= row_bytes.len() {
                result.push((col.name.clone(), 0));
                continue;
            }
            if row_bytes[offset] == 0x00 {
                is_null = true;
            }
            offset += 1;
        }

        if is_null {
            result.push((col.name.clone(), 0));
            continue;
        }

        let width = match col.col_type.fixed_byte_width() {
            Some(w) => w,
            None => {
                if offset + 4 <= row_bytes.len() {
                    let mut len_buf = [0u8; 4];
                    len_buf.copy_from_slice(&row_bytes[offset..offset + 4]);
                    let text_len = u32::from_le_bytes(len_buf) as usize;
                    offset += 4 + text_len;
                }
                result.push((col.name.clone(), 0));
                continue;
            }
        };

        if offset + width <= row_bytes.len() {
            let val = read_le_u64(&row_bytes[offset..offset + width], &col.col_type);
            result.push((col.name.clone(), val));
            offset += width;
        } else {
            result.push((col.name.clone(), 0));
        }
    }

    result
}

/// Read a fixed-width column value as u64 (little-endian).
fn read_le_u64(bytes: &[u8], col_type: &ColumnType) -> u64 {
    match col_type {
        ColumnType::Bool => bytes.first().copied().unwrap_or(0) as u64,
        ColumnType::U8 | ColumnType::I8 => bytes.first().copied().unwrap_or(0) as u64,
        ColumnType::U16 | ColumnType::I16 => {
            let mut buf = [0u8; 2];
            buf[..bytes.len().min(2)].copy_from_slice(&bytes[..bytes.len().min(2)]);
            u16::from_le_bytes(buf) as u64
        }
        ColumnType::U32 | ColumnType::I32 | ColumnType::F32 => {
            let mut buf = [0u8; 4];
            buf[..bytes.len().min(4)].copy_from_slice(&bytes[..bytes.len().min(4)]);
            u32::from_le_bytes(buf) as u64
        }
        ColumnType::U64 | ColumnType::I64 | ColumnType::F64 | ColumnType::Timestamp => {
            let mut buf = [0u8; 8];
            buf[..bytes.len().min(8)].copy_from_slice(&bytes[..bytes.len().min(8)]);
            u64::from_le_bytes(buf)
        }
        ColumnType::Uuid => {
            // Take first 8 bytes of UUID as u64
            let mut buf = [0u8; 8];
            buf[..bytes.len().min(8)].copy_from_slice(&bytes[..bytes.len().min(8)]);
            u64::from_le_bytes(buf)
        }
        _ => 0,
    }
}
