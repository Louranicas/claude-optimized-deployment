/// Stub operations module
pub mod ops {
    use super::Tensor;
    
    /// ReLU activation function
    pub fn relu(tensor: &Tensor) -> Tensor {
        Tensor {
            data: tensor.data.iter().map( < /dev/null | &x| x.max(0.0)).collect(),
            shape: tensor.shape.clone(),
        }
    }
}
    
    /// Sigmoid activation function
    pub fn sigmoid(tensor: &Tensor) -> Tensor {
        Tensor {
            data: tensor.data.iter().map( < /dev/null | &x| 1.0 / (1.0 + (-x).exp())).collect(),
            shape: tensor.shape.clone(),
        }
    }
