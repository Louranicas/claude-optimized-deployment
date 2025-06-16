//! Stub implementations for ML functionality when ML features are disabled
//!
//! Provides minimal implementations to maintain API compatibility

use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Enum for tensor shapes
#[derive(Debug, Clone)]
pub enum TensorShape {
    D1(usize),
    D2(usize, usize),
}

impl From<(usize,)> for TensorShape {
    fn from(shape: (usize,)) -> Self {
        TensorShape::D1(shape.0)
    }
}

impl From<(usize, usize)> for TensorShape {
    fn from(shape: (usize, usize)) -> Self {
        TensorShape::D2(shape.0, shape.1)
    }
}

// Re-export from tensor module if available
#[cfg(feature = "tensor_stub")]
pub use crate::synthex_bashgod::memory::tensor_stub::{Device, Tensor, DType};

#[cfg(not(feature = "tensor_stub"))]
#[derive(Debug, Clone)]
pub struct Device;

#[cfg(not(feature = "tensor_stub"))]
impl Device {
    pub fn cpu() -> Self { Device }
    pub fn cuda_if_available() -> Self { Device }
}

#[cfg(not(feature = "tensor_stub"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tensor {
    pub data: Vec<f32>,
    pub shape: Vec<usize>,
}

#[cfg(not(feature = "tensor_stub"))]
#[derive(Debug, Clone, Copy)]
pub enum DType {
    F32,
    F64,
    I32,
    I64,
}

#[cfg(not(feature = "tensor_stub"))]
impl Tensor {
    pub fn zeros(shape: &[usize], _dtype: DType, _device: &Device) -> Result<Self, String> {
        let size = shape.iter().product();
        Ok(Self {
            data: vec![0.0; size],
            shape: shape.to_vec(),
        })
    }
    
    pub fn from_slice(data: &[f32], shape: &[usize], _device: &Device) -> Result<Self, String> {
        if data.len() != shape.iter().product::<usize>() {
            return Err("Data length doesn't match shape".to_string());
        }
        Ok(Self {
            data: data.to_vec(),
            shape: shape.to_vec(),
        })
    }
    
    pub fn to_vec1(&self) -> Result<Vec<f32>, String> {
        Ok(self.data.clone())
    }
    
    pub fn shape(&self) -> &[usize] {
        &self.shape
    }
    
    pub fn apply<F>(&self, f: F) -> Self 
    where
        F: Fn(&Tensor) -> Tensor,
    {
        f(self)
    }
    
    pub fn matmul(&self, other: &Self) -> Result<Self, String> {
        if self.shape.len() != 2 || other.shape.len() != 2 {
            return Err("Can only multiply 2D tensors".to_string());
        }
        
        let m = self.shape[0];
        let n = self.shape[1];
        let p = other.shape[1];
        
        if n != other.shape[0] {
            return Err("Incompatible shapes for matrix multiplication".to_string());
        }
        
        let mut result = vec![0.0; m * p];
        
        for i in 0..m {
            for j in 0..p {
                let mut sum = 0.0;
                for k in 0..n {
                    sum += self.data[i * n + k] * other.data[k * p + j];
                }
                result[i * p + j] = sum;
            }
        }
        
        Ok(Self {
            data: result,
            shape: vec![m, p],
        })
    }
}

/// Stub for module trait
pub trait Module {
    fn forward(&self, input: &Tensor) -> Result<Tensor, String>;
}

/// Stub for Linear layer
#[derive(Debug, Clone)]
pub struct Linear {
    weights: Tensor,
    bias: Vec<f32>,
    in_features: usize,
    out_features: usize,
}

impl Linear {
    pub fn new(weights: Tensor, bias: Option<Tensor>) -> Self {
        let shape = weights.shape();
        let in_features = shape[1];
        let out_features = shape[0];
        let bias_vec = bias.map_or_else(
            || vec![0.0; out_features], 
            |b| b.data
        );
        
        Self {
            weights,
            bias: bias_vec,
            in_features,
            out_features,
        }
    }
}

impl Module for Linear {
    fn forward(&self, input: &Tensor) -> Result<Tensor, String> {
        // Simplified: just return a tensor of the right shape
        let batch_size = input.shape[0];
        let mut output = vec![0.0; batch_size * self.out_features];
        
        // Simplified computation
        for b in 0..batch_size {
            for o in 0..self.out_features {
                output[b * self.out_features + o] = self.bias[o];
            }
        }
        
        Ok(Tensor {
            data: output,
            shape: vec![batch_size, self.out_features],
        })
    }
}

/// Stub for VarBuilder
#[derive(Debug, Clone)]
pub struct VarBuilder {
    var_map: Arc<VarMap>,
}

impl VarBuilder {
    pub fn from_varmap(var_map: &VarMap, _dtype: DType, _device: &Device) -> Self {
        Self {
            var_map: Arc::new(var_map.clone()),
        }
    }
    
    pub fn get(&self, shape: impl Into<TensorShape>, _name: &str) -> Result<Tensor, String> {
        match shape.into() {
            TensorShape::D1(size) => Ok(Tensor {
                data: vec![0.1; size],
                shape: vec![size],
            }),
            TensorShape::D2(rows, cols) => {
                let size = rows * cols;
                Ok(Tensor {
                    data: vec![0.1; size],
                    shape: vec![rows, cols],
                })
            }
        }
    }
    
    pub fn get_with_hints(&self, shape: usize, _name: &str, _hints: ()) -> Result<Tensor, String> {
        Ok(Tensor {
            data: vec![0.0; shape],
            shape: vec![shape],
        })
    }
}

/// Stub for VarMap
#[derive(Debug, Clone)]
pub struct VarMap {
    data: std::collections::HashMap<String, Vec<f32>>,
}

impl VarMap {
    pub fn new() -> Self {
        Self {
            data: std::collections::HashMap::new(),
        }
    }
    
    pub fn save(&self, _path: &std::path::Path) -> Result<(), String> {
        Ok(())
    }
    
    pub fn load(&mut self, _path: &std::path::Path) -> Result<(), String> {
        Ok(())
    }
}

impl Default for VarMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Stub operations module
pub mod ops {
    use super::Tensor;
    
    /// ReLU activation function
    pub fn relu(tensor: &Tensor) -> Tensor {
        Tensor {
            data: tensor.data.iter().map(|&x| x.max(0.0)).collect(),
            shape: tensor.shape.clone(),
        }
    }
    
    /// Sigmoid activation function
    pub fn sigmoid(tensor: &Tensor) -> Tensor {
        Tensor {
            data: tensor.data.iter().map(|&x| 1.0 / (1.0 + (-x).exp())).collect(),
            shape: tensor.shape.clone(),
        }
    }
}