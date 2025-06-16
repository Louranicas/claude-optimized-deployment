// ============================================================================
// PATTERN ANALYSIS - Advanced Pattern Recognition and Insight Extraction
// ============================================================================
// This module implements sophisticated pattern analysis algorithms to extract
// key insights, trends, and anomalies from expert responses using parallel
// processing and statistical analysis techniques.
// ============================================================================

use crate::circle_of_experts::{ExpertResponse};
use crate::circle_of_experts::aggregator::AggregatedResponse;
use crate::CoreError;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};

/// Statistical pattern information
#[derive(Debug, Clone)]
pub struct PatternStats {
    pub frequency: usize,
    pub confidence_mean: f32,
    pub confidence_std: f32,
    pub expert_coverage: f32,
}

/// Extract key insights from expert responses
pub fn extract_key_insights(
    responses: &[ExpertResponse],
    aggregated: &AggregatedResponse,
) -> Result<Vec<String>, CoreError> {
    if responses.is_empty() {
        return Ok(Vec::new());
    }
    
    let mut insights = Vec::new();
    
    // Analyze response patterns
    let patterns = analyze_response_patterns(responses)?;
    insights.extend(format_pattern_insights(&patterns));
    
    // Detect anomalies and outliers
    let anomalies = detect_anomalies(responses)?;
    insights.extend(format_anomaly_insights(&anomalies));
    
    // Extract temporal trends if timestamps are meaningful
    if has_temporal_variance(responses) {
        let trends = analyze_temporal_trends(responses)?;
        insights.extend(format_temporal_insights(&trends));
    }
    
    // Analyze confidence distribution
    let confidence_insights = analyze_confidence_distribution(responses)?;
    insights.extend(confidence_insights);
    
    // Extract domain-specific insights
    let domain_insights = extract_domain_insights(responses, aggregated)?;
    insights.extend(domain_insights);
    
    // Limit to top insights
    Ok(insights.into_iter().take(10).collect())
}

/// Analyze patterns in expert responses
fn analyze_response_patterns(responses: &[ExpertResponse]) -> Result<HashMap<String, PatternStats>, CoreError> {
    // Extract all meaningful phrases in parallel
    let all_phrases: Vec<HashMap<String, usize>> = responses
        .par_iter()
        .map(|response| extract_meaningful_phrases(&response.content))
        .collect();
    
    // Aggregate pattern statistics
    let mut pattern_stats: HashMap<String, Vec<(String, f32)>> = HashMap::new();
    
    for (idx, phrases) in all_phrases.iter().enumerate() {
        let expert_name = &responses[idx].expert_name;
        let confidence = responses[idx].confidence;
        
        for (phrase, count) in phrases {
            pattern_stats
                .entry(phrase.clone())
                .or_insert_with(Vec::new)
                .push((expert_name.clone(), confidence));
        }
    }
    
    // Calculate statistics for each pattern
    let mut patterns = HashMap::new();
    let total_experts = responses.len() as f32;
    
    for (phrase, expert_data) in pattern_stats {
        let frequency = expert_data.len();
        if frequency < 2 {
            continue; // Skip patterns that appear only once
        }
        
        let confidences: Vec<f32> = expert_data.iter().map(|(_, conf)| *conf).collect();
        let confidence_mean = confidences.iter().sum::<f32>() / confidences.len() as f32;
        let confidence_std = calculate_std_dev(&confidences, confidence_mean);
        let expert_coverage = frequency as f32 / total_experts;
        
        patterns.insert(
            phrase,
            PatternStats {
                frequency,
                confidence_mean,
                confidence_std,
                expert_coverage,
            },
        );
    }
    
    Ok(patterns)
}

/// Extract meaningful phrases with semantic weight
fn extract_meaningful_phrases(text: &str) -> HashMap<String, usize> {
    let mut phrases = HashMap::new();
    let sentences: Vec<&str> = text.split(|c| c == '.' || c == '!' || c == '?').collect();
    
    for sentence in sentences {
        let words: Vec<&str> = sentence
            .split_whitespace()
            .filter(|w| w.len() > 2)
            .collect();
        
        // Extract noun phrases (simplified)
        for i in 0..words.len() {
            // Single important words
            if is_important_word(words[i]) {
                *phrases.entry(words[i].to_lowercase()).or_insert(0) += 1;
            }
            
            // Bigrams with important words
            if i + 1 < words.len() && (is_important_word(words[i]) || is_important_word(words[i + 1])) {
                let bigram = format!("{} {}", words[i], words[i + 1]).to_lowercase();
                *phrases.entry(bigram).or_insert(0) += 1;
            }
            
            // Trigrams with at least one important word
            if i + 2 < words.len() {
                let has_important = is_important_word(words[i]) 
                    || is_important_word(words[i + 1]) 
                    || is_important_word(words[i + 2]);
                if has_important {
                    let trigram = format!("{} {} {}", words[i], words[i + 1], words[i + 2]).to_lowercase();
                    *phrases.entry(trigram).or_insert(0) += 1;
                }
            }
        }
    }
    
    phrases
}

/// Check if a word is semantically important
fn is_important_word(word: &str) -> bool {
    // Simple heuristic: longer words and capitalized words are often important
    word.len() > 5 || word.chars().next().map_or(false, |c| c.is_uppercase())
}

/// Detect anomalies in expert responses
fn detect_anomalies(responses: &[ExpertResponse]) -> Result<Vec<(String, String)>, CoreError> {
    let mut anomalies = Vec::new();
    
    // Detect confidence outliers
    let confidences: Vec<f32> = responses.iter().map(|r| r.confidence).collect();
    let mean_confidence = confidences.iter().sum::<f32>() / confidences.len() as f32;
    let std_confidence = calculate_std_dev(&confidences, mean_confidence);
    
    for response in responses {
        let z_score = (response.confidence - mean_confidence) / std_confidence;
        if z_score.abs() > 2.0 {
            anomalies.push((
                response.expert_name.clone(),
                format!("Unusual confidence level: {:.2} (z-score: {:.2})", response.confidence, z_score),
            ));
        }
    }
    
    // Detect response length outliers
    let lengths: Vec<usize> = responses.iter().map(|r| r.content.len()).collect();
    let mean_length = lengths.iter().sum::<usize>() / lengths.len();
    let length_floats: Vec<f32> = lengths.iter().map(|&l| l as f32).collect();
    let std_length = calculate_std_dev(&length_floats, mean_length as f32);
    
    for (idx, response) in responses.iter().enumerate() {
        let z_score = (lengths[idx] as f32 - mean_length as f32) / std_length;
        if z_score.abs() > 2.0 {
            anomalies.push((
                response.expert_name.clone(),
                format!("Unusual response length: {} characters (z-score: {:.2})", lengths[idx], z_score),
            ));
        }
    }
    
    Ok(anomalies)
}

/// Analyze temporal trends if timestamps vary
fn analyze_temporal_trends(responses: &[ExpertResponse]) -> Result<Vec<(String, f32)>, CoreError> {
    let mut trends = Vec::new();
    
    // Sort responses by timestamp
    let mut sorted_responses = responses.to_vec();
    sorted_responses.sort_by_key(|r| r.timestamp);
    
    // Analyze confidence trend over time
    let confidence_trend = calculate_trend(&sorted_responses.iter().map(|r| r.confidence).collect::<Vec<_>>());
    if confidence_trend.abs() > 0.1 {
        trends.push((
            format!("Confidence {} over time", if confidence_trend > 0.0 { "increasing" } else { "decreasing" }),
            confidence_trend,
        ));
    }
    
    // Analyze response length trend
    let length_trend = calculate_trend(&sorted_responses.iter().map(|r| r.content.len() as f32).collect::<Vec<_>>());
    if length_trend.abs() > 10.0 {
        trends.push((
            format!("Response length {} over time", if length_trend > 0.0 { "increasing" } else { "decreasing" }),
            length_trend / 100.0, // Normalize
        ));
    }
    
    Ok(trends)
}

/// Check if responses have meaningful temporal variance
fn has_temporal_variance(responses: &[ExpertResponse]) -> bool {
    if responses.len() < 2 {
        return false;
    }
    
    let timestamps: Vec<u64> = responses.iter().map(|r| r.timestamp).collect();
    let min_time = *timestamps.iter().min().unwrap();
    let max_time = *timestamps.iter().max().unwrap();
    
    // Consider temporal if spread is more than 1 minute
    max_time - min_time > 60
}

/// Calculate trend using simple linear regression
fn calculate_trend(values: &[f32]) -> f32 {
    if values.len() < 2 {
        return 0.0;
    }
    
    let n = values.len() as f32;
    let x_mean = (n - 1.0) / 2.0;
    let y_mean = values.iter().sum::<f32>() / n;
    
    let mut numerator = 0.0;
    let mut denominator = 0.0;
    
    for (i, &y) in values.iter().enumerate() {
        let x = i as f32;
        numerator += (x - x_mean) * (y - y_mean);
        denominator += (x - x_mean) * (x - x_mean);
    }
    
    if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    }
}

/// Analyze confidence distribution
fn analyze_confidence_distribution(responses: &[ExpertResponse]) -> Result<Vec<String>, CoreError> {
    let mut insights = Vec::new();
    let confidences: Vec<f32> = responses.iter().map(|r| r.confidence).collect();
    
    let mean = confidences.iter().sum::<f32>() / confidences.len() as f32;
    let std_dev = calculate_std_dev(&confidences, mean);
    
    // High consensus
    if std_dev < 0.1 {
        insights.push(format!("High consensus: All experts show similar confidence levels (σ={:.3})", std_dev));
    }
    
    // Polarized opinions
    if std_dev > 0.3 {
        insights.push(format!("Polarized opinions: Expert confidence varies significantly (σ={:.3})", std_dev));
    }
    
    // Confidence distribution
    let high_confidence = confidences.iter().filter(|&&c| c > 0.8).count();
    let low_confidence = confidences.iter().filter(|&&c| c < 0.5).count();
    
    if high_confidence > responses.len() * 3 / 4 {
        insights.push(format!("{:.0}% of experts show high confidence (>0.8)", 
            high_confidence as f32 / responses.len() as f32 * 100.0));
    }
    
    if low_confidence > responses.len() / 4 {
        insights.push(format!("{:.0}% of experts show low confidence (<0.5)", 
            low_confidence as f32 / responses.len() as f32 * 100.0));
    }
    
    Ok(insights)
}

/// Extract domain-specific insights
fn extract_domain_insights(
    responses: &[ExpertResponse],
    aggregated: &AggregatedResponse,
) -> Result<Vec<String>, CoreError> {
    let mut insights = Vec::new();
    
    // Analyze expert diversity
    let unique_experts: HashSet<&str> = responses.iter().map(|r| r.expert_name.as_str()).collect();
    if unique_experts.len() >= 5 {
        insights.push(format!("Broad expert consensus from {} different AI models", unique_experts.len()));
    }
    
    // Analyze consensus vs dissent ratio
    let consensus_size = aggregated.contributing_experts.len();
    let dissent_size = aggregated.dissenting_opinions.len();
    
    if dissent_size > 0 {
        let ratio = consensus_size as f32 / (consensus_size + dissent_size) as f32;
        insights.push(format!("Consensus ratio: {:.0}% agreement, {} alternative viewpoints", 
            ratio * 100.0, dissent_size));
    }
    
    Ok(insights)
}

/// Calculate standard deviation
fn calculate_std_dev(values: &[f32], mean: f32) -> f32 {
    if values.is_empty() {
        return 0.0;
    }
    
    let variance = values
        .iter()
        .map(|&value| (value - mean).powi(2))
        .sum::<f32>() / values.len() as f32;
    
    variance.sqrt()
}

/// Format pattern insights
fn format_pattern_insights(patterns: &HashMap<String, PatternStats>) -> Vec<String> {
    let mut insights = Vec::new();
    
    // Sort patterns by relevance (frequency * confidence * coverage)
    let mut sorted_patterns: Vec<(&String, &PatternStats)> = patterns.iter().collect();
    sorted_patterns.sort_by(|a, b| {
        let score_a = a.1.frequency as f32 * a.1.confidence_mean * a.1.expert_coverage;
        let score_b = b.1.frequency as f32 * b.1.confidence_mean * b.1.expert_coverage;
        score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal)
    });
    
    for (phrase, stats) in sorted_patterns.iter().take(3) {
        insights.push(format!(
            "Key theme '{}': mentioned by {:.0}% of experts with {:.2} avg confidence",
            phrase, stats.expert_coverage * 100.0, stats.confidence_mean
        ));
    }
    
    insights
}

/// Format anomaly insights
fn format_anomaly_insights(anomalies: &[(String, String)]) -> Vec<String> {
    anomalies
        .iter()
        .take(2)
        .map(|(expert, anomaly)| format!("{}: {}", expert, anomaly))
        .collect()
}

/// Format temporal insights
fn format_temporal_insights(trends: &[(String, f32)]) -> Vec<String> {
    trends
        .iter()
        .map(|(description, magnitude)| format!("{} (trend: {:.2})", description, magnitude))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    
    #[test]
    fn test_calculate_std_dev() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let mean = 3.0;
        let std_dev = calculate_std_dev(&values, mean);
        assert!((std_dev - 1.414).abs() < 0.01);
    }
    
    #[test]
    fn test_calculate_trend() {
        let increasing = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let trend = calculate_trend(&increasing);
        assert!(trend > 0.9); // Should be close to 1.0
        
        let decreasing = vec![5.0, 4.0, 3.0, 2.0, 1.0];
        let trend = calculate_trend(&decreasing);
        assert!(trend < -0.9); // Should be close to -1.0
    }
    
    #[test]
    fn test_extract_meaningful_phrases() {
        let text = "The artificial intelligence system performs complex analysis. AI systems are evolving rapidly.";
        let phrases = extract_meaningful_phrases(text);
        
        assert!(phrases.contains_key("artificial"));
        assert!(phrases.contains_key("intelligence"));
        assert!(phrases.contains_key("artificial intelligence"));
    }
}