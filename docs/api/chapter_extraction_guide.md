# Chapter Extraction API Guide

## Overview

The Chapter Extraction API provides comprehensive tools for extracting, processing, and managing document chapters through multiple interfaces:

- **RESTful API**: Standard HTTP endpoints for direct integration
- **GraphQL API**: Flexible queries for complex data requirements  
- **WebSocket API**: Real-time updates and progress monitoring
- **MCP Tools**: Standardized AI model integration
- **Event-driven API**: File monitoring with automatic extraction

## Quick Start

### Authentication

All API endpoints require authentication via API key:

```bash
curl -H "X-API-Key: your-api-key" \
     -H "Content-Type: application/json" \
     https://api.synthex.ai/v1/chapters/extract
```

### Basic Chapter Extraction

Extract chapters from text content:

```bash
curl -X POST https://api.synthex.ai/v1/chapters/extract \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Chapter 1: Introduction\n\nThis is the first chapter...\n\nChapter 2: Methodology\n\nThis describes the methodology...",
    "config": {
      "chapter_pattern": "^Chapter\\s+(\\d+)",
      "min_chapter_length": 50
    },
    "output_format": "json"
  }'
```

Response:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "chapters": [
    {
      "metadata": {
        "id": "ch-001",
        "title": "Chapter 1: Introduction",
        "number": 1,
        "start_line": 0,
        "end_line": 2,
        "word_count": 24,
        "character_count": 156
      },
      "content": "This is the first chapter...",
      "subsections": []
    }
  ],
  "total_chapters": 2
}
```

## RESTful API Reference

### Extract Chapters

**POST** `/api/v1/chapters/extract`

Extract chapters from various content sources.

#### Request Body

```json
{
  "content": "string",           // Direct text content (optional)
  "file_path": "string",        // Local file path (optional) 
  "url": "string",              // URL to fetch content (optional)
  "config": {
    "chapter_pattern": "string",         // Regex pattern for chapters
    "section_pattern": "string",         // Regex pattern for sections
    "min_chapter_length": 100,           // Minimum chapter length
    "max_chapter_length": 50000,         // Maximum chapter length
    "include_metadata": true,            // Include chapter metadata
    "preserve_formatting": true,         // Preserve original formatting
    "extract_subsections": true,         // Extract nested subsections
    "custom_patterns": ["string"]        // Additional patterns
  },
  "output_format": "json",      // Export format: json, markdown, html
  "async_processing": false     // Process asynchronously
}
```

#### Response

```json
{
  "job_id": "uuid",
  "status": "completed|pending|processing|failed",
  "chapters": [/* Chapter objects */],
  "total_chapters": 0,
  "processing_time": 1.23,
  "error": "string",
  "export_url": "string"
}
```

### Upload File Extraction

**POST** `/api/v1/chapters/extract/file`

Extract chapters from uploaded files.

```bash
curl -X POST https://api.synthex.ai/v1/chapters/extract/file \
  -H "X-API-Key: your-api-key" \
  -F "file=@document.txt" \
  -F 'config={"chapter_pattern": "^Chapter\\s+(\\d+)"}' \
  -F "output_format=markdown"
```

### Batch Processing

**POST** `/api/v1/chapters/batch`

Process multiple files simultaneously.

```json
{
  "files": [
    "/path/to/document1.txt",
    "/path/to/document2.pdf"
  ],
  "config": {
    "chapter_pattern": "^Chapter\\s+(\\d+)",
    "min_chapter_length": 100
  },
  "parallel_processing": true,
  "max_concurrent": 5
}
```

### Search Chapters

**POST** `/api/v1/chapters/search`

Search through extracted chapters with advanced filtering.

```json
{
  "query": "introduction methodology",
  "filters": {
    "min_words": 100,
    "max_words": 5000,
    "tags": ["research", "science"],
    "job_id": "uuid"
  },
  "limit": 10,
  "offset": 0,
  "sort_by": "relevance",
  "include_content": false
}
```

Response:
```json
{
  "query": "introduction methodology",
  "total_results": 42,
  "results": [
    {
      "job_id": "uuid",
      "chapter_id": "uuid", 
      "title": "Chapter 1: Introduction",
      "score": 0.95,
      "snippet": "...highlighted text...",
      "word_count": 250,
      "tags": ["introduction"]
    }
  ],
  "facets": {
    "tags": {"research": 15, "science": 8},
    "word_count_ranges": {"0-1000": 12, "1000-5000": 20}
  }
}
```

### Export Chapters

**GET** `/api/v1/chapters/export/{job_id}/{format}`

Export chapters in various formats.

```bash
# Export as Markdown
curl -H "X-API-Key: your-api-key" \
     https://api.synthex.ai/v1/chapters/export/job-uuid/markdown

# Export as HTML  
curl -H "X-API-Key: your-api-key" \
     https://api.synthex.ai/v1/chapters/export/job-uuid/html
```

### File Monitoring

**POST** `/api/v1/chapters/monitor`

Start monitoring files for automatic extraction.

```json
{
  "path": "/path/to/watch",
  "config": {
    "chapter_pattern": "^Chapter\\s+(\\d+)"
  },
  "recursive": true,
  "file_patterns": ["*.txt", "*.md"],
  "webhook_url": "https://your-app.com/webhook"
}
```

## WebSocket API

Connect to receive real-time updates:

```javascript
const ws = new WebSocket('wss://api.synthex.ai/v1/chapters/ws/client-123');

// Subscribe to job updates
ws.send(JSON.stringify({
  type: 'subscribe',
  job_id: 'your-job-id'
}));

// Start extraction with progress updates
ws.send(JSON.stringify({
  type: 'extract',
  request: {
    content: 'Chapter 1: Introduction...',
    config: {
      chapter_pattern: '^Chapter\\s+(\\d+)'
    }
  }
}));

// Handle messages
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  switch(data.type) {
    case 'progress':
      console.log(`Progress: ${data.progress}%`);
      break;
    case 'completed':
      console.log('Extraction completed:', data.result);
      break;
    case 'error':
      console.error('Error:', data.error);
      break;
  }
};
```

## GraphQL API

### Basic Query

```graphql
query GetChapters($jobId: ID!) {
  chapters(jobId: $jobId) {
    id
    metadata {
      title
      number
      wordCount
      tags
    }
    contentPreview
    subsections {
      id
      metadata {
        title
        level
      }
    }
  }
}
```

### Search Query

```graphql
query SearchChapters($query: String!, $filters: SearchFiltersInput) {
  searchChapters(query: $query, filters: $filters) {
    totalResults
    results {
      chapter {
        id
        metadata {
          title
          wordCount
        }
      }
      score
      snippet
    }
    facets {
      name
      value
      count
    }
  }
}
```

### Extraction Mutation

```graphql
mutation ExtractChapters($source: String!, $config: ExtractionConfigInput) {
  extractChapters(source: $source, config: $config) {
    success
    job {
      id
      status
      totalChapters
      chapters {
        id
        metadata {
          title
          wordCount
        }
      }
    }
    error
  }
}
```

### Subscription for Real-time Updates

```graphql
subscription JobUpdates($jobId: ID!) {
  jobStatusUpdated(jobId: $jobId) {
    id
    status
    progress
    totalChapters
    error
  }
}
```

## MCP Tools

### Extract Chapters Tool

```json
{
  "tool": "extract_chapters",
  "parameters": {
    "source": "Chapter 1: Introduction\n\nContent...",
    "source_type": "text",
    "chapter_pattern": "^Chapter\\s+(\\d+)",
    "min_chapter_length": 100,
    "output_format": "json"
  }
}
```

### Search Chapters Tool

```json
{
  "tool": "search_chapters", 
  "parameters": {
    "query": "methodology research",
    "min_words": 200,
    "limit": 5,
    "sort_by": "relevance"
  }
}
```

### Analyze Document Structure Tool

```json
{
  "tool": "analyze_chapter_structure",
  "parameters": {
    "source": "/path/to/document.txt",
    "source_type": "file",
    "include_statistics": true,
    "detect_patterns": true
  }
}
```

### Batch Extraction Tool

```json
{
  "tool": "batch_extract_chapters",
  "parameters": {
    "sources": [
      {"path": "/path/doc1.txt", "source_type": "file"},
      {"path": "/path/doc2.pdf", "source_type": "file"}
    ],
    "config": {
      "chapter_pattern": "^Chapter\\s+(\\d+)",
      "min_chapter_length": 100
    },
    "parallel_processing": true,
    "max_concurrent": 3
  }
}
```

## Configuration Options

### Chapter Patterns

Common regex patterns for chapter detection:

```javascript
// Standard numbered chapters
"^Chapter\\s+(\\d+)"                    // "Chapter 1", "Chapter 2"
"^CHAPTER\\s+(\\d+)"                    // "CHAPTER 1", "CHAPTER 2"

// Numbered sections
"^(\\d+)\\."                            // "1.", "2.", "3."
"^(\\d+\\.\\d+)"                        // "1.1", "1.2", "2.1"

// Markdown headers
"^#+\\s+"                               // "#", "##", "###"

// Roman numerals
"^Chapter\\s+([IVX]+)"                  // "Chapter I", "Chapter II"

// Custom patterns
"^Part\\s+(\\d+)"                       // "Part 1", "Part 2"
"^Section\\s+(\\w+)"                    // "Section A", "Section B"
```

### Advanced Configuration

```json
{
  "chapter_pattern": "^Chapter\\s+(\\d+)",
  "section_pattern": "^Section\\s+(\\d+\\.\\d+)",
  "min_chapter_length": 100,
  "max_chapter_length": 50000,
  "include_metadata": true,
  "preserve_formatting": true,
  "extract_subsections": true,
  "custom_patterns": [
    "^Appendix\\s+([A-Z])",
    "^Bibliography",
    "^References"
  ]
}
```

## Error Handling

### Common Error Codes

| Code | Description | Solution |
|------|-------------|----------|
| `validation_error` | Invalid input parameters | Check request format and patterns |
| `pattern_error` | Invalid regex pattern | Verify regex syntax |
| `file_not_found` | Source file not accessible | Check file path and permissions |
| `rate_limit_exceeded` | Too many requests | Wait and retry with backoff |
| `processing_timeout` | Extraction took too long | Use async processing or smaller chunks |

### Error Response Format

```json
{
  "error": "validation_error",
  "message": "Invalid regex pattern in chapter_pattern",
  "details": {
    "field": "config.chapter_pattern",
    "value": "^(Chapter",
    "expected": "Valid regex pattern"
  },
  "request_id": "req_123abc"
}
```

## Rate Limits

| Endpoint | Rate Limit | Burst Limit |
|----------|------------|-------------|
| Extract (sync) | 10/minute | 20 |
| Extract (async) | 60/minute | 100 |
| Search | 60/minute | 120 |
| File upload | 20/minute | 30 |
| WebSocket | 1 connection/user | - |

## SDK Examples

### Python SDK

```python
from synthex_api import ChapterExtractionClient

client = ChapterExtractionClient(api_key="your-api-key")

# Extract chapters
result = await client.extract_chapters(
    content="Chapter 1: Introduction...",
    config={
        "chapter_pattern": r"^Chapter\s+(\d+)",
        "min_chapter_length": 100
    }
)

# Search chapters
search_results = await client.search_chapters(
    query="methodology",
    filters={"min_words": 200},
    limit=10
)

# Monitor files
monitor = await client.start_monitoring(
    path="/path/to/docs",
    config={"chapter_pattern": r"^Chapter\s+(\d+)"},
    webhook_url="https://your-app.com/webhook"
)
```

### JavaScript SDK

```javascript
import { ChapterExtractionClient } from '@synthex/api';

const client = new ChapterExtractionClient({
  apiKey: 'your-api-key',
  baseURL: 'https://api.synthex.ai/v1'
});

// Extract chapters
const result = await client.extractChapters({
  content: 'Chapter 1: Introduction...',
  config: {
    chapterPattern: '^Chapter\\s+(\\d+)',
    minChapterLength: 100
  }
});

// Real-time extraction with WebSocket
const ws = client.createWebSocketConnection();
ws.on('progress', (data) => {
  console.log(`Progress: ${data.progress}%`);
});

ws.extractChapters({
  content: 'Chapter 1: Introduction...',
  config: { chapterPattern: '^Chapter\\s+(\\d+)' }
});
```

## Best Practices

### Pattern Design

1. **Start Simple**: Begin with basic patterns and refine based on results
2. **Test Patterns**: Use the analysis tool to validate patterns before extraction
3. **Consider Edge Cases**: Account for variations in formatting and numbering
4. **Use Anchors**: Always anchor patterns with `^` to match line beginnings

### Performance Optimization

1. **Use Async Processing**: For large documents, enable async processing
2. **Batch Operations**: Process multiple files together for better throughput
3. **Cache Results**: Cache frequently accessed extractions
4. **Optimize Patterns**: Simpler patterns process faster than complex ones

### Content Handling

1. **Validate Input**: Always validate and sanitize input content
2. **Handle Encoding**: Ensure proper text encoding for international content
3. **Manage Memory**: Use streaming for very large documents
4. **Error Recovery**: Implement retry logic for transient failures

## Webhooks

Configure webhooks to receive notifications:

### Chapter Extracted Event

```json
{
  "event": "chapter_extracted",
  "job_id": "uuid",
  "chapters": [/* chapter objects */],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### File Changed Event

```json
{
  "event": "file_changed", 
  "monitor_id": "uuid",
  "path": "/path/to/changed/file.txt",
  "change_type": "modified",
  "chapters": [/* extracted chapters */],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Troubleshooting

### Common Issues

1. **No Chapters Found**
   - Check if pattern matches your content format
   - Verify minimum length requirements
   - Use analysis tool to detect document structure

2. **Incorrect Chapter Boundaries**
   - Refine regex pattern specificity
   - Check for nested sections or subsections
   - Review content formatting consistency

3. **Performance Issues**
   - Enable async processing for large documents
   - Reduce batch size or concurrent operations
   - Optimize regex patterns for efficiency

4. **Memory Errors**
   - Process documents in smaller chunks
   - Use streaming for very large files
   - Increase server memory limits if needed

### Debug Mode

Enable debug logging for detailed extraction information:

```json
{
  "content": "...",
  "config": {
    "debug": true,
    "log_level": "debug"
  }
}
```

## Support

- **Documentation**: https://docs.synthex.ai/chapter-extraction
- **API Reference**: https://api.synthex.ai/docs
- **Support**: support@synthex.ai
- **Status Page**: https://status.synthex.ai