// ============================================================================
// Command Chain Module - Building and Parsing Bash Command Chains
// ============================================================================

use std::fmt;
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

/// Represents a chain of bash commands with operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandChain {
    pub id: String,
    pub elements: Vec<ChainElement>,
    pub env_vars: Vec<(String, String)>,
    pub working_dir: Option<String>,
}

/// Elements in a command chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainElement {
    Command(String),
    Pipe,
    And,
    Or,
    Semicolon,
    Background,
    Redirect(RedirectType),
    Subshell(CommandChain),
}

/// Types of redirections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RedirectType {
    Output(String),          // >
    Append(String),          // >>
    Input(String),           // <
    ErrorToOutput,           // 2>&1
    OutputToError,           // 1>&2
    HereDoc(String),         // <<
}

impl CommandChain {
    /// Create a new command chain
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            elements: Vec::new(),
            env_vars: Vec::new(),
            working_dir: None,
        }
    }

    /// Add a command to the chain
    pub fn add_command(&mut self, command: String) {
        self.elements.push(ChainElement::Command(command));
    }

    /// Add a pipe operator
    pub fn pipe(&mut self) {
        self.elements.push(ChainElement::Pipe);
    }

    /// Add an AND operator
    pub fn and(&mut self) {
        self.elements.push(ChainElement::And);
    }

    /// Add an OR operator
    pub fn or(&mut self) {
        self.elements.push(ChainElement::Or);
    }

    /// Add a semicolon
    pub fn semicolon(&mut self) {
        self.elements.push(ChainElement::Semicolon);
    }

    /// Add a background operator
    pub fn background(&mut self) {
        self.elements.push(ChainElement::Background);
    }

    /// Add output redirection
    pub fn redirect_output(&mut self, target: String) {
        self.elements.push(ChainElement::Redirect(RedirectType::Output(target)));
    }

    /// Add append redirection
    pub fn redirect_append(&mut self, target: String) {
        self.elements.push(ChainElement::Redirect(RedirectType::Append(target)));
    }

    /// Add input redirection
    pub fn redirect_input(&mut self, source: String) {
        self.elements.push(ChainElement::Redirect(RedirectType::Input(source)));
    }

    /// Redirect stderr to stdout
    pub fn redirect_error_to_output(&mut self) {
        self.elements.push(ChainElement::Redirect(RedirectType::ErrorToOutput));
    }

    /// Add a subshell
    pub fn add_subshell(&mut self, chain: CommandChain) {
        self.elements.push(ChainElement::Subshell(chain));
    }

    /// Set an environment variable
    pub fn set_env(&mut self, key: String, value: String) {
        self.env_vars.push((key, value));
    }

    /// Set working directory
    pub fn set_cwd(&mut self, path: String) {
        self.working_dir = Some(path);
    }

    /// Parse a command chain from a string
    pub fn from_string(input: &str) -> Result<Self> {
        let parser = CommandChainParser::new(input);
        parser.parse()
    }

    /// Validate the command chain
    pub fn validate(&self) -> Result<()> {
        if self.elements.is_empty() {
            return Err(anyhow!("Command chain is empty"));
        }

        // Check for invalid operator sequences
        let mut prev_was_operator = true;
        for element in &self.elements {
            match element {
                ChainElement::Command(_) | ChainElement::Subshell(_) => {
                    prev_was_operator = false;
                }
                ChainElement::Pipe | ChainElement::And | ChainElement::Or | ChainElement::Semicolon => {
                    if prev_was_operator {
                        return Err(anyhow!("Invalid operator sequence"));
                    }
                    prev_was_operator = true;
                }
                _ => {}
            }
        }

        if prev_was_operator && !matches!(self.elements.last(), Some(ChainElement::Background)) {
            return Err(anyhow!("Command chain ends with an operator"));
        }

        Ok(())
    }

    /// Clone with a new ID
    pub fn clone_with_new_id(&self) -> Self {
        let mut chain = self.clone();
        chain.id = Uuid::new_v4().to_string();
        chain
    }
}

impl fmt::Display for CommandChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut result = String::new();

        // Add environment variables
        for (key, value) in &self.env_vars {
            result.push_str(&format!("{}='{}' ", key, value));
        }

        // Add working directory change if specified
        if let Some(cwd) = &self.working_dir {
            result.push_str(&format!("cd '{}' && ", cwd));
        }

        // Build the command chain
        for (i, element) in self.elements.iter().enumerate() {
            if i > 0 {
                result.push(' ');
            }

            match element {
                ChainElement::Command(cmd) => result.push_str(cmd),
                ChainElement::Pipe => result.push_str("|"),
                ChainElement::And => result.push_str("&&"),
                ChainElement::Or => result.push_str("||"),
                ChainElement::Semicolon => result.push_str(";"),
                ChainElement::Background => result.push('&'),
                ChainElement::Redirect(redirect) => {
                    match redirect {
                        RedirectType::Output(target) => result.push_str(&format!("> {}", target)),
                        RedirectType::Append(target) => result.push_str(&format!(">> {}", target)),
                        RedirectType::Input(source) => result.push_str(&format!("< {}", source)),
                        RedirectType::ErrorToOutput => result.push_str("2>&1"),
                        RedirectType::OutputToError => result.push_str("1>&2"),
                        RedirectType::HereDoc(delimiter) => result.push_str(&format!("<< {}", delimiter)),
                    }
                }
                ChainElement::Subshell(chain) => {
                    result.push_str(&format!("({})", chain));
                }
            }
        }

        write!(f, "{}", result)
    }
}

/// Parser for command chains
struct CommandChainParser {
    input: String,
    position: usize,
}

impl CommandChainParser {
    fn new(input: &str) -> Self {
        Self {
            input: input.to_string(),
            position: 0,
        }
    }

    fn parse(mut self) -> Result<CommandChain> {
        let mut chain = CommandChain::new();
        
        // Parse environment variables at the beginning
        self.parse_env_vars(&mut chain)?;
        
        // Parse the main command chain
        self.parse_elements(&mut chain)?;
        
        chain.validate()?;
        Ok(chain)
    }

    fn parse_env_vars(&mut self, chain: &mut CommandChain) -> Result<()> {
        // Simple env var parsing - can be enhanced
        while let Some((key, value)) = self.try_parse_env_var()? {
            chain.set_env(key, value);
        }
        Ok(())
    }

    fn try_parse_env_var(&mut self) -> Result<Option<(String, String)>> {
        // This is a simplified parser - in production, use a proper shell parser
        self.skip_whitespace();
        
        let start = self.position;
        
        // Look for KEY=VALUE pattern
        if let Some(eq_pos) = self.input[self.position..].find('=') {
            let key = self.input[self.position..self.position + eq_pos].trim().to_string();
            
            // Check if key is valid (alphanumeric + underscore)
            if key.chars().all(|c| c.is_alphanumeric() || c == '_') && !key.is_empty() {
                self.position += eq_pos + 1;
                
                // Parse value (handle quotes)
                let value = self.parse_value()?;
                
                return Ok(Some((key, value)));
            }
        }
        
        self.position = start;
        Ok(None)
    }

    fn parse_value(&mut self) -> Result<String> {
        self.skip_whitespace();
        
        if self.position >= self.input.len() {
            return Ok(String::new());
        }

        let first_char = self.input.chars().nth(self.position).unwrap();
        
        if first_char == '\'' {
            // Single quoted string
            self.parse_single_quoted()
        } else if first_char == '"' {
            // Double quoted string
            self.parse_double_quoted()
        } else {
            // Unquoted value
            self.parse_unquoted_value()
        }
    }

    fn parse_single_quoted(&mut self) -> Result<String> {
        self.position += 1; // Skip opening quote
        
        if let Some(end) = self.input[self.position..].find('\'') {
            let value = self.input[self.position..self.position + end].to_string();
            self.position += end + 1;
            Ok(value)
        } else {
            Err(anyhow!("Unterminated single quote"))
        }
    }

    fn parse_double_quoted(&mut self) -> Result<String> {
        self.position += 1; // Skip opening quote
        
        let mut value = String::new();
        let mut escaped = false;
        
        for ch in self.input[self.position..].chars() {
            if escaped {
                value.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                self.position += value.len() + 1;
                return Ok(value);
            } else {
                value.push(ch);
            }
        }
        
        Err(anyhow!("Unterminated double quote"))
    }

    fn parse_unquoted_value(&mut self) -> Result<String> {
        let mut value = String::new();
        
        for ch in self.input[self.position..].chars() {
            if ch.is_whitespace() || "|&;<>()".contains(ch) {
                break;
            }
            value.push(ch);
        }
        
        self.position += value.len();
        Ok(value)
    }

    fn parse_elements(&mut self, chain: &mut CommandChain) -> Result<()> {
        while self.position < self.input.len() {
            self.skip_whitespace();
            
            if self.position >= self.input.len() {
                break;
            }

            // Parse operators
            if self.try_parse_operator(chain)? {
                continue;
            }

            // Parse redirections
            if self.try_parse_redirection(chain)? {
                continue;
            }

            // Parse subshell
            if self.try_parse_subshell(chain)? {
                continue;
            }

            // Parse command
            self.parse_command(chain)?;
        }

        Ok(())
    }

    fn try_parse_operator(&mut self, chain: &mut CommandChain) -> Result<bool> {
        let remaining = &self.input[self.position..];
        
        if remaining.starts_with("&&") {
            chain.and();
            self.position += 2;
            Ok(true)
        } else if remaining.starts_with("||") {
            chain.or();
            self.position += 2;
            Ok(true)
        } else if remaining.starts_with("2>&1") {
            chain.redirect_error_to_output();
            self.position += 4;
            Ok(true)
        } else if remaining.starts_with("1>&2") {
            chain.elements.push(ChainElement::Redirect(RedirectType::OutputToError));
            self.position += 4;
            Ok(true)
        } else if remaining.starts_with(">>") {
            self.position += 2;
            self.skip_whitespace();
            let target = self.parse_value()?;
            chain.redirect_append(target);
            Ok(true)
        } else if remaining.starts_with("|") {
            chain.pipe();
            self.position += 1;
            Ok(true)
        } else if remaining.starts_with(";") {
            chain.semicolon();
            self.position += 1;
            Ok(true)
        } else if remaining.starts_with("&") && !remaining.starts_with("&&") {
            chain.background();
            self.position += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn try_parse_redirection(&mut self, chain: &mut CommandChain) -> Result<bool> {
        let remaining = &self.input[self.position..];
        
        if remaining.starts_with("<<") {
            self.position += 2;
            self.skip_whitespace();
            let delimiter = self.parse_value()?;
            chain.elements.push(ChainElement::Redirect(RedirectType::HereDoc(delimiter)));
            Ok(true)
        } else if remaining.starts_with(">") {
            self.position += 1;
            self.skip_whitespace();
            let target = self.parse_value()?;
            chain.redirect_output(target);
            Ok(true)
        } else if remaining.starts_with("<") {
            self.position += 1;
            self.skip_whitespace();
            let source = self.parse_value()?;
            chain.redirect_input(source);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn try_parse_subshell(&mut self, chain: &mut CommandChain) -> Result<bool> {
        if self.input[self.position..].starts_with('(') {
            self.position += 1;
            
            // Find matching closing parenthesis
            let mut depth = 1;
            let start = self.position;
            
            while depth > 0 && self.position < self.input.len() {
                match self.input.chars().nth(self.position) {
                    Some('(') => depth += 1,
                    Some(')') => depth -= 1,
                    Some('\'') => self.skip_single_quoted()?,
                    Some('"') => self.skip_double_quoted()?,
                    _ => {}
                }
                self.position += 1;
            }
            
            if depth != 0 {
                return Err(anyhow!("Unmatched parenthesis"));
            }
            
            let subshell_input = &self.input[start..self.position - 1];
            let subshell = CommandChain::from_string(subshell_input)?;
            chain.add_subshell(subshell);
            
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn parse_command(&mut self, chain: &mut CommandChain) -> Result<()> {
        let mut command = String::new();
        
        while self.position < self.input.len() {
            let ch = self.input.chars().nth(self.position).unwrap();
            
            if "|&;<>()".contains(ch) || (ch == '2' && self.input[self.position..].starts_with("2>&1")) {
                break;
            }
            
            if ch == '\'' {
                command.push_str(&self.parse_single_quoted()?);
            } else if ch == '"' {
                command.push_str(&self.parse_double_quoted()?);
            } else if ch.is_whitespace() {
                if !command.is_empty() {
                    command.push(ch);
                }
                self.position += 1;
            } else {
                command.push(ch);
                self.position += 1;
            }
        }
        
        let command = command.trim().to_string();
        if !command.is_empty() {
            chain.add_command(command);
        }
        
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        while self.position < self.input.len() {
            if !self.input.chars().nth(self.position).unwrap().is_whitespace() {
                break;
            }
            self.position += 1;
        }
    }

    fn skip_single_quoted(&mut self) -> Result<()> {
        self.position += 1;
        while self.position < self.input.len() {
            if self.input.chars().nth(self.position) == Some('\'') {
                self.position += 1;
                return Ok(());
            }
            self.position += 1;
        }
        Err(anyhow!("Unterminated single quote"))
    }

    fn skip_double_quoted(&mut self) -> Result<()> {
        self.position += 1;
        let mut escaped = false;
        
        while self.position < self.input.len() {
            let ch = self.input.chars().nth(self.position).unwrap();
            
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                self.position += 1;
                return Ok(());
            }
            
            self.position += 1;
        }
        
        Err(anyhow!("Unterminated double quote"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_command() {
        let mut chain = CommandChain::new();
        chain.add_command("echo 'Hello World'".to_string());
        assert_eq!(chain.to_string(), "echo 'Hello World'");
    }

    #[test]
    fn test_pipe_chain() {
        let mut chain = CommandChain::new();
        chain.add_command("ls -la".to_string());
        chain.pipe();
        chain.add_command("grep test".to_string());
        assert_eq!(chain.to_string(), "ls -la | grep test");
    }

    #[test]
    fn test_parse_complex_chain() {
        let input = "VAR=value ls -la | grep test && echo 'Done' || echo 'Failed'";
        let chain = CommandChain::from_string(input).unwrap();
        assert_eq!(chain.env_vars.len(), 1);
        assert_eq!(chain.env_vars[0], ("VAR".to_string(), "value".to_string()));
    }
}