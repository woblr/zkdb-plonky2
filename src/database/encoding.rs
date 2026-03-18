//! Canonical row encoding.
//!
//! Every row must be encoded deterministically into a byte sequence
//! (and a corresponding field-element sequence) before being committed
//! into a Merkle tree. The encoding must be:
//!   - Deterministic: same row → same bytes across all machines and runs.
//!   - Injective: different rows → different byte sequences (no collisions).
//!   - Versioned: `encoding_spec_version` is stored in the snapshot manifest.

use crate::database::schema::DatasetSchema;
use crate::field::{bytes_to_fields, FieldElement};
use crate::types::{ColumnType, ZkDbError, ZkResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ─────────────────────────────────────────────────────────────────────────────
// Raw and canonical row types
// ─────────────────────────────────────────────────────────────────────────────

/// A raw row as received from an ingestion source (JSON Value array).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawRow {
    pub row_index: u64,
    /// Column values in schema column order.
    pub values: Vec<Value>,
}

/// A validated and canonically encoded row, ready for Merkle commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalRow {
    pub row_index: u64,
    /// Deterministic little-endian byte encoding.
    pub bytes: Vec<u8>,
    /// One FieldElement per byte (for circuit use).
    pub field_elements: Vec<FieldElement>,
}

impl CanonicalRow {
    /// Blake3 leaf hash of this row's canonical bytes.
    pub fn leaf_hash(&self) -> [u8; 32] {
        *blake3::hash(&self.bytes).as_bytes()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RowEncoder trait
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes validated rows into canonical byte form.
pub trait RowEncoder: Send + Sync {
    fn encode(&self, row: &RawRow, schema: &DatasetSchema) -> ZkResult<CanonicalRow>;

    fn encode_batch(&self, rows: &[RawRow], schema: &DatasetSchema) -> ZkResult<Vec<CanonicalRow>> {
        rows.iter().map(|r| self.encode(r, schema)).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Default implementation (encoding spec v1)
// ─────────────────────────────────────────────────────────────────────────────

/// Canonical encoding spec v1:
///
/// Each column is encoded left-to-right.
/// Nullable columns are prefixed with 1 byte: 0x00 = NULL, 0x01 = present.
/// Fixed-width types: little-endian bytes.
/// Text/Bytes: 4-byte LE length prefix, then UTF-8 bytes.
/// Timestamp: i64 millis, 8 bytes LE.
/// UUID: 16 raw bytes.
pub struct DefaultRowEncoder;

impl RowEncoder for DefaultRowEncoder {
    fn encode(&self, row: &RawRow, schema: &DatasetSchema) -> ZkResult<CanonicalRow> {
        if row.values.len() != schema.columns.len() {
            return Err(ZkDbError::Encoding(format!(
                "row {} has {} values but schema has {} columns",
                row.row_index,
                row.values.len(),
                schema.columns.len()
            )));
        }

        let mut buf = Vec::with_capacity(64);

        // Prefix: row index (8 bytes LE) for uniqueness across chunks.
        buf.extend_from_slice(&row.row_index.to_le_bytes());

        for (col, val) in schema.columns.iter().zip(row.values.iter()) {
            encode_value(
                &mut buf,
                val,
                &col.col_type,
                col.nullable,
                &col.name,
                row.row_index,
            )?;
        }

        let field_elements = bytes_to_fields(&buf);
        Ok(CanonicalRow {
            row_index: row.row_index,
            bytes: buf,
            field_elements,
        })
    }
}

fn encode_value(
    buf: &mut Vec<u8>,
    val: &Value,
    col_type: &ColumnType,
    nullable: bool,
    col_name: &str,
    row_index: u64,
) -> ZkResult<()> {
    // Null handling
    if val.is_null() {
        if !nullable {
            return Err(ZkDbError::Encoding(format!(
                "column '{}' is NOT NULL but row {} has null value",
                col_name, row_index
            )));
        }
        buf.push(0x00); // null sentinel
        return Ok(());
    }
    if nullable {
        buf.push(0x01); // present sentinel
    }

    match col_type {
        ColumnType::Bool => {
            let b = val
                .as_bool()
                .ok_or_else(|| enc_err(col_name, row_index, "expected bool"))?;
            buf.push(b as u8);
        }
        ColumnType::U8 => {
            let n = parse_u64(val, col_name, row_index)?;
            if n > u8::MAX as u64 {
                return Err(enc_err(col_name, row_index, "value out of range for u8"));
            }
            buf.push(n as u8);
        }
        ColumnType::U16 => {
            let n = parse_u64(val, col_name, row_index)? as u16;
            buf.extend_from_slice(&n.to_le_bytes());
        }
        ColumnType::U32 => {
            let n = parse_u64(val, col_name, row_index)? as u32;
            buf.extend_from_slice(&n.to_le_bytes());
        }
        ColumnType::U64 => {
            let n = parse_u64(val, col_name, row_index)?;
            buf.extend_from_slice(&n.to_le_bytes());
        }
        ColumnType::I8 => {
            let n = parse_i64(val, col_name, row_index)? as i8;
            buf.push(n as u8);
        }
        ColumnType::I16 => {
            let n = parse_i64(val, col_name, row_index)? as i16;
            buf.extend_from_slice(&n.to_le_bytes());
        }
        ColumnType::I32 => {
            let n = parse_i64(val, col_name, row_index)? as i32;
            buf.extend_from_slice(&n.to_le_bytes());
        }
        ColumnType::I64 => {
            let n = parse_i64(val, col_name, row_index)?;
            buf.extend_from_slice(&n.to_le_bytes());
        }
        ColumnType::F32 => {
            let n = val
                .as_f64()
                .ok_or_else(|| enc_err(col_name, row_index, "expected number for f32"))?
                as f32;
            buf.extend_from_slice(&n.to_le_bytes());
        }
        ColumnType::F64 => {
            let n = val
                .as_f64()
                .ok_or_else(|| enc_err(col_name, row_index, "expected number for f64"))?;
            buf.extend_from_slice(&n.to_le_bytes());
        }
        ColumnType::Decimal { .. } => {
            // Store as f64 for now; a production impl would use fixed-point.
            let n = val
                .as_f64()
                .ok_or_else(|| enc_err(col_name, row_index, "expected number for decimal"))?;
            buf.extend_from_slice(&n.to_le_bytes());
        }
        ColumnType::Text { max_bytes } => {
            let s = val
                .as_str()
                .ok_or_else(|| enc_err(col_name, row_index, "expected string for Text"))?;
            let bytes = s.as_bytes();
            if let Some(max) = max_bytes {
                if bytes.len() > *max as usize {
                    return Err(enc_err(col_name, row_index, "text exceeds max_bytes"));
                }
            }
            let len = bytes.len() as u32;
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(bytes);
        }
        ColumnType::Bytes { max_len } => {
            let s = val
                .as_str()
                .ok_or_else(|| enc_err(col_name, row_index, "expected hex string for Bytes"))?;
            let decoded = hex::decode(s)
                .map_err(|_| enc_err(col_name, row_index, "invalid hex for Bytes"))?;
            if let Some(max) = max_len {
                if decoded.len() > *max as usize {
                    return Err(enc_err(col_name, row_index, "bytes exceed max_len"));
                }
            }
            let len = decoded.len() as u32;
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(&decoded);
        }
        ColumnType::Timestamp => {
            let n = parse_i64(val, col_name, row_index)?;
            buf.extend_from_slice(&n.to_le_bytes());
        }
        ColumnType::Uuid => {
            let s = val
                .as_str()
                .ok_or_else(|| enc_err(col_name, row_index, "expected UUID string"))?;
            let u: uuid::Uuid = s
                .parse()
                .map_err(|_| enc_err(col_name, row_index, "invalid UUID"))?;
            buf.extend_from_slice(u.as_bytes());
        }
    }
    Ok(())
}

fn parse_u64(val: &Value, col: &str, row: u64) -> ZkResult<u64> {
    val.as_u64()
        .ok_or_else(|| enc_err(col, row, "expected non-negative integer"))
}

fn parse_i64(val: &Value, col: &str, row: u64) -> ZkResult<i64> {
    val.as_i64()
        .ok_or_else(|| enc_err(col, row, "expected integer"))
}

fn enc_err(col: &str, row: u64, msg: &str) -> ZkDbError {
    ZkDbError::Encoding(format!("column '{}', row {}: {}", col, row, msg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::schema::ColumnSchema;
    use crate::types::DatasetId;

    fn schema_with(cols: Vec<ColumnSchema>) -> DatasetSchema {
        DatasetSchema::new(DatasetId::new(), "test", cols)
    }

    #[test]
    fn encode_u64_deterministic() {
        let schema = schema_with(vec![ColumnSchema::new("id", ColumnType::U64)]);
        let row = RawRow {
            row_index: 0,
            values: vec![Value::Number(42u64.into())],
        };
        let enc = DefaultRowEncoder;
        let r1 = enc.encode(&row, &schema).unwrap();
        let r2 = enc.encode(&row, &schema).unwrap();
        assert_eq!(r1.bytes, r2.bytes);
    }

    #[test]
    fn null_on_non_nullable_fails() {
        let schema = schema_with(vec![ColumnSchema::new("id", ColumnType::U64)]);
        let row = RawRow {
            row_index: 0,
            values: vec![Value::Null],
        };
        let enc = DefaultRowEncoder;
        assert!(enc.encode(&row, &schema).is_err());
    }

    #[test]
    fn null_on_nullable_succeeds() {
        let schema = schema_with(vec![ColumnSchema::new("val", ColumnType::I64).nullable()]);
        let row = RawRow {
            row_index: 0,
            values: vec![Value::Null],
        };
        let enc = DefaultRowEncoder;
        assert!(enc.encode(&row, &schema).is_ok());
    }
}
