//! Tipos de valor suportados pelo scanner.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ValueType {
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
    F32,
    F64,
}

impl ValueType {
    pub const ALL: [ValueType; 10] = [
        ValueType::I8,
        ValueType::I16,
        ValueType::I32,
        ValueType::I64,
        ValueType::U8,
        ValueType::U16,
        ValueType::U32,
        ValueType::U64,
        ValueType::F32,
        ValueType::F64,
    ];

    pub fn size(&self) -> usize {
        match self {
            ValueType::I8 | ValueType::U8 => 1,
            ValueType::I16 | ValueType::U16 => 2,
            ValueType::I32 | ValueType::U32 | ValueType::F32 => 4,
            ValueType::I64 | ValueType::U64 | ValueType::F64 => 8,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ValueType::I8 => "Byte (i8)",
            ValueType::I16 => "2 Bytes (i16)",
            ValueType::I32 => "4 Bytes (i32)",
            ValueType::I64 => "8 Bytes (i64)",
            ValueType::U8 => "Byte (u8)",
            ValueType::U16 => "2 Bytes (u16)",
            ValueType::U32 => "4 Bytes (u32)",
            ValueType::U64 => "8 Bytes (u64)",
            ValueType::F32 => "Float (f32)",
            ValueType::F64 => "Double (f64)",
        }
    }

    /// Converte um texto digitado pelo usuario nos bytes que serao procurados.
    pub fn parse_to_bytes(&self, text: &str) -> Option<Vec<u8>> {
        let t = text.trim();
        Some(match self {
            ValueType::I8 => t.parse::<i8>().ok()?.to_le_bytes().to_vec(),
            ValueType::I16 => t.parse::<i16>().ok()?.to_le_bytes().to_vec(),
            ValueType::I32 => t.parse::<i32>().ok()?.to_le_bytes().to_vec(),
            ValueType::I64 => t.parse::<i64>().ok()?.to_le_bytes().to_vec(),
            ValueType::U8 => t.parse::<u8>().ok()?.to_le_bytes().to_vec(),
            ValueType::U16 => t.parse::<u16>().ok()?.to_le_bytes().to_vec(),
            ValueType::U32 => t.parse::<u32>().ok()?.to_le_bytes().to_vec(),
            ValueType::U64 => t.parse::<u64>().ok()?.to_le_bytes().to_vec(),
            ValueType::F32 => t.parse::<f32>().ok()?.to_le_bytes().to_vec(),
            ValueType::F64 => t.parse::<f64>().ok()?.to_le_bytes().to_vec(),
        })
    }

    /// Le os bytes como um numero f64 (moeda universal para comparacao/exibicao).
    /// Retorna None se nao houver bytes suficientes.
    pub fn read_f64(&self, bytes: &[u8]) -> Option<f64> {
        if bytes.len() < self.size() {
            return None;
        }
        Some(match self {
            ValueType::I8 => i8::from_le_bytes(bytes[..1].try_into().ok()?) as f64,
            ValueType::I16 => i16::from_le_bytes(bytes[..2].try_into().ok()?) as f64,
            ValueType::I32 => i32::from_le_bytes(bytes[..4].try_into().ok()?) as f64,
            ValueType::I64 => i64::from_le_bytes(bytes[..8].try_into().ok()?) as f64,
            ValueType::U8 => u8::from_le_bytes(bytes[..1].try_into().ok()?) as f64,
            ValueType::U16 => u16::from_le_bytes(bytes[..2].try_into().ok()?) as f64,
            ValueType::U32 => u32::from_le_bytes(bytes[..4].try_into().ok()?) as f64,
            ValueType::U64 => u64::from_le_bytes(bytes[..8].try_into().ok()?) as f64,
            ValueType::F32 => f32::from_le_bytes(bytes[..4].try_into().ok()?) as f64,
            ValueType::F64 => f64::from_le_bytes(bytes[..8].try_into().ok()?),
        })
    }

    pub fn format(&self, bytes: &[u8]) -> String {
        match self.read_f64(bytes) {
            Some(v) => {
                if matches!(self, ValueType::F32 | ValueType::F64) {
                    format!("{v}")
                } else {
                    format!("{}", v as i64)
                }
            }
            None => "?".into(),
        }
    }
}
