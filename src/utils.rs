/// A trait for building query and body parameters in a string.
pub trait ParamBuilder {
    /// Appends a key-value pair to the string as a query parameter. If the
    /// string doesn't contain any query parameters, it adds a '?' character.
    /// Otherwise, it appends '&'.
    #[must_use]
    fn push_param_query(self, key: impl AsRef<str>, value: impl AsRef<str>) -> Self;

    /// Appends a key-value pair to the string as a body parameter.
    /// It always appends '&'.
    #[must_use]
    fn push_param_body(self, key: impl AsRef<str>, value: impl AsRef<str>) -> Self;
}

/// Implementation of the `ParamBuilder` trait for the `String` type.
impl ParamBuilder for String {
    /// Appends a key-value pair to the string as a query parameter.
    fn push_param_query(mut self, key: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        if !self.contains('?') {
            self.push('?');
        } else if !self.ends_with('&') {
            self.push('&');
        }
        self.push_str(key.as_ref());
        self.push('=');
        self.push_str(value.as_ref());
        self
    }

    /// Appends a key-value pair to the string as a body parameter.
    fn push_param_body(mut self, key: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        self.push('&');
        self.push_str(key.as_ref());
        self.push('=');
        self.push_str(value.as_ref());
        self
    }
}
