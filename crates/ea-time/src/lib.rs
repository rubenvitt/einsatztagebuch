#![forbid(unsafe_code)]

mod error;
mod evaluate;
mod model;

pub use error::TimeError;
pub use evaluate::{
    advance_registry_floor, evaluate_preexisting_time, merge_independent_references,
};
pub use model::{
    FutureSkew, IndependentTimeInput, IndependentTimeKind, IndependentTimeReference, TimeAdvance,
    TimeEvaluation, TimeWarnings, TrustedTimeState,
};
