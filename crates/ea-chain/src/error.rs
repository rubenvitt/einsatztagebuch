use core::fmt;

/// Eingabefehler des Aufrufers von [`build_chain`](crate::build_chain).
///
/// Diese Variante beschreibt AUSSCHLIESSLICH eine unzulaessige Eingabe, nie
/// einen Befund ueber den Bestand. Bruch, Luecke und Fork sind Befunde und
/// erscheinen als Diagnose in [`VerifiedChain`](crate::VerifiedChain), also im
/// `Ok`-Zweig.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum ChainError {
    /// Ein Knoten traegt eine andere `chain_id` als die geforderte.
    ForeignChainId,
    /// Sequenz 0 traegt einen Vorgaengerhash oder Sequenz > 0 traegt keinen.
    GenesisBinding,
    /// Die Knotenzahl uebersteigt [`MAX_CHAIN_NODES_V1`](crate::MAX_CHAIN_NODES_V1).
    NodeLimit,
}

impl ChainError {
    /// Stabiler Fehlercode. Tests assertieren gegen ihn, nie gegen Formatierung.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ForeignChainId => "EA-CHAIN-FOREIGN-CHAIN-ID",
            Self::GenesisBinding => "EA-CHAIN-GENESIS-BINDING",
            Self::NodeLimit => "EA-CHAIN-NODE-LIMIT",
        }
    }
}

impl fmt::Display for ChainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for ChainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ChainError {}
