#[derive(Clone, Debug, PartialEq)]
pub enum OutputKind<T> {
    Default {
        header: bool,
    },
    Parseable {
        header: bool,
        fields: Vec<T>,
        separator: ParseableOutputSeparator,
    },
}

impl<T> OutputKind<T> {
    pub fn with_header(header: bool) -> Self {
        OutputKind::Default { header }
    }

    pub fn parseable(
        header: bool,
        fields: Vec<T>,
        separator: Option<String>,
    ) -> Self {
        OutputKind::Parseable {
            header,
            fields,
            separator: ParseableOutputSeparator::new(separator),
        }
    }

    pub fn display_header(&self) -> bool {
        match self {
            Self::Default { header } => *header,
            Self::Parseable { header, .. } => *header,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ParseableOutputSeparator {
    Default,
    Custom(String),
}

impl ParseableOutputSeparator {
    pub fn new(custom_value: Option<String>) -> Self {
        match custom_value {
            Some(value) => ParseableOutputSeparator::Custom(value),
            None => ParseableOutputSeparator::Default,
        }
    }
}

impl ParseableOutputSeparator {
    pub fn as_str(&self) -> &str {
        match self {
            ParseableOutputSeparator::Default => ":",
            ParseableOutputSeparator::Custom(s) => s.as_str(),
        }
    }
}
