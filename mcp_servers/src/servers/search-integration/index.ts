import { BaseMCPServer } from '../../core/base-server';
import { z } from 'zod';
import axios from 'axios';
import { config } from '../../core/config';

// Schema definitions
const SearchSchema = z.object({
  query: z.string(),
  searchEngine: z.enum(['tavily', 'brave', 'all']).optional().default('all'),
  maxResults: z.number().optional().default(10),
  searchDepth: z.enum(['basic', 'advanced']).optional().default('basic'),
  includeImages: z.boolean().optional().default(false),
  includeAnswer: z.boolean().optional().default(true),
  searchType: z.enum(['web', 'news', 'academic']).optional().default('web'),
});

const CodeSearchSchema = z.object({
  query: z.string(),
  language: z.string().optional(),
  repositories: z.array(z.string()).optional(),
  includeDocumentation: z.boolean().optional().default(true),
});

// Note: TavilySearchResult and BraveSearchResult interfaces moved inline where needed

export class SearchIntegrationServer extends BaseMCPServer {
  private tavilyApiKey: string;
  private braveApiKey: string;
  
  constructor() {
    super({
      name: 'search-integration',
      version: '1.0.0',
      description: 'MCP server for integrated search capabilities using Tavily and Brave',
    });
    
    this.tavilyApiKey = config.tavily.apiKey;
    this.braveApiKey = config.brave.apiKey;
  }
  
  protected async setupTools(): Promise<void> {
    // Tool: Web Search
    this.registerTool({
      name: 'web_search',
      description: 'Search the web using Tavily and/or Brave search engines',
      inputSchema: {
        type: 'object',
        properties: {
          query: { type: 'string', description: 'Search query' },
          searchEngine: { 
            type: 'string',
            enum: ['tavily', 'brave', 'all'],
            description: 'Which search engine to use (default: all)'
          },
          maxResults: { 
            type: 'number',
            description: 'Maximum number of results (default: 10)'
          },
          searchDepth: {
            type: 'string',
            enum: ['basic', 'advanced'],
            description: 'Search depth (default: basic)'
          },
          includeImages: {
            type: 'boolean',
            description: 'Include image results (default: false)'
          },
          includeAnswer: {
            type: 'boolean',
            description: 'Include AI-generated answer (default: true)'
          },
          searchType: {
            type: 'string',
            enum: ['web', 'news', 'academic'],
            description: 'Type of search (default: web)'
          },
        },
        required: ['query'],
      },
    });
    
    // Tool: Code Search
    this.registerTool({
      name: 'code_search',
      description: 'Search for code examples, documentation, and programming solutions',
      inputSchema: {
        type: 'object',
        properties: {
          query: { type: 'string', description: 'Code search query' },
          language: { type: 'string', description: 'Programming language filter' },
          repositories: { 
            type: 'array',
            items: { type: 'string' },
            description: 'Specific repositories to search'
          },
          includeDocumentation: {
            type: 'boolean',
            description: 'Include documentation in results (default: true)'
          },
        },
        required: ['query'],
      },
    });
    
    // Tool: Research Assistant
    this.registerTool({
      name: 'research_assistant',
      description: 'Conduct comprehensive research on a topic with summarized findings',
      inputSchema: {
        type: 'object',
        properties: {
          topic: { type: 'string', description: 'Research topic' },
          questions: {
            type: 'array',
            items: { type: 'string' },
            description: 'Specific questions to answer'
          },
          depth: {
            type: 'string',
            enum: ['quick', 'standard', 'comprehensive'],
            description: 'Research depth (default: standard)'
          },
          sources: {
            type: 'array',
            items: { type: 'string' },
            description: 'Preferred sources or domains'
          },
        },
        required: ['topic'],
      },
    });
    
    // Tool: Real-time Information
    this.registerTool({
      name: 'realtime_info',
      description: 'Get real-time information about current events, weather, stocks, etc.',
      inputSchema: {
        type: 'object',
        properties: {
          infoType: {
            type: 'string',
            enum: ['news', 'weather', 'stocks', 'sports', 'crypto'],
            description: 'Type of real-time information'
          },
          query: { type: 'string', description: 'Specific query or location' },
          timeframe: {
            type: 'string',
            enum: ['latest', 'today', 'week', 'month'],
            description: 'Time frame for information (default: latest)'
          },
        },
        required: ['infoType', 'query'],
      },
    });
  }
  
  protected async executeTool(name: string, args: unknown): Promise<unknown> {
    switch (name) {
      case 'web_search':
        return this.webSearch(args);
      case 'code_search':
        return this.codeSearch(args);
      case 'research_assistant':
        return this.researchAssistant(args);
      case 'realtime_info':
        return this.realtimeInfo(args);
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }
  
  private async webSearch(args: unknown) {
    const params = SearchSchema.parse(args);
    const results = {
      query: params.query,
      results: [] as any[],
      answer: null as string | null,
      metadata: {
        searchEngine: params.searchEngine,
        totalResults: 0,
        searchTime: 0,
      },
    };
    
    const startTime = Date.now();
    
    // Search with Tavily
    if (params.searchEngine === 'tavily' || params.searchEngine === 'all') {
      try {
        const tavilyResults = await this.searchWithTavily(
          params.query,
          params.maxResults,
          params.searchDepth,
          params.includeAnswer,
          params.searchType
        );
        results.results.push(...tavilyResults.results);
        if (tavilyResults.answer) {
          results.answer = tavilyResults.answer;
        }
      } catch (error) {
        this.logger.error({ error }, 'Tavily search failed');
      }
    }
    
    // Search with Brave
    if (params.searchEngine === 'brave' || params.searchEngine === 'all') {
      try {
        const braveResults = await this.searchWithBrave(
          params.query,
          params.maxResults,
          params.searchType
        );
        results.results.push(...braveResults);
      } catch (error) {
        this.logger.error({ error }, 'Brave search failed');
      }
    }
    
    // Remove duplicates and sort by relevance
    results.results = this.deduplicateAndSort(results.results);
    results.metadata.totalResults = results.results.length;
    results.metadata.searchTime = Date.now() - startTime;
    
    return results;
  }
  
  private async searchWithTavily(
    query: string,
    maxResults: number,
    searchDepth: string,
    includeAnswer: boolean,
    searchType: string
  ) {
    const response = await axios.post(
      'https://api.tavily.com/search',
      {
        api_key: this.tavilyApiKey,
        query,
        search_depth: searchDepth,
        include_answer: includeAnswer,
        include_images: false,
        max_results: maxResults,
        search_type: searchType,
      }
    );
    
    return {
      results: response.data.results.map((r: any) => ({
        title: r.title,
        url: r.url,
        content: r.content,
        score: r.score,
        source: 'tavily',
        publishedDate: r.published_date,
      })),
      answer: response.data.answer,
    };
  }
  
  private async searchWithBrave(
    query: string,
    maxResults: number,
    searchType: string
  ) {
    const endpoint = searchType === 'news' 
      ? 'https://api.search.brave.com/res/v1/news/search'
      : 'https://api.search.brave.com/res/v1/web/search';
      
    const response = await axios.get(endpoint, {
      headers: {
        'X-Subscription-Token': this.braveApiKey,
      },
      params: {
        q: query,
        count: maxResults,
      },
    });
    
    const results = searchType === 'news' 
      ? response.data.results
      : response.data.web?.results || [];
      
    return results.map((r: any) => ({
      title: r.title,
      url: r.url,
      content: r.description || r.snippet,
      score: r.relevance_score || 0.5,
      source: 'brave',
      publishedDate: r.age || r.published,
    }));
  }
  
  private deduplicateAndSort(results: any[]) {
    // Remove duplicates based on URL
    const seen = new Set();
    const unique = results.filter(r => {
      if (seen.has(r.url)) return false;
      seen.add(r.url);
      return true;
    });
    
    // Sort by score (relevance)
    return unique.sort((a, b) => (b.score || 0) - (a.score || 0));
  }
  
  private async codeSearch(args: unknown) {
    const params = CodeSearchSchema.parse(args);
    
    // Build search query with language filter
    let searchQuery = params.query;
    if (params.language) {
      searchQuery = `${params.query} language:${params.language} site:github.com OR site:stackoverflow.com OR site:dev.to`;
    }
    
    // Add repository filter if specified
    if (params.repositories && params.repositories.length > 0) {
      const repoFilter = params.repositories
        .map(repo => `site:github.com/${repo}`)
        .join(' OR ');
      searchQuery = `${params.query} (${repoFilter})`;
    }
    
    // Search for code examples
    const codeResults = await this.webSearch({
      query: searchQuery,
      searchEngine: 'all',
      maxResults: 20,
      searchDepth: 'advanced',
      includeAnswer: true,
    });
    
    // Filter and enhance results for code-specific content
    const enhancedResults = codeResults.results
      .filter((r: any) => {
        // Filter for code-related content
        const codeIndicators = ['github.com', 'stackoverflow.com', 'dev.to', 'medium.com'];
        return codeIndicators.some(indicator => r.url.includes(indicator));
      })
      .map((r: any) => ({
        ...r,
        type: this.detectCodeType(r.url),
        language: params.language || this.detectLanguage(r.content),
      }));
    
    // Search documentation if requested
    let documentationResults = [];
    if (params.includeDocumentation) {
      const docQuery = `${params.query} documentation official docs`;
      const docSearch = await this.webSearch({
        query: docQuery,
        searchEngine: 'all',
        maxResults: 5,
        searchDepth: 'basic',
      });
      documentationResults = docSearch.results;
    }
    
    return {
      query: params.query,
      language: params.language,
      codeExamples: enhancedResults,
      documentation: documentationResults,
      summary: codeResults.answer,
      metadata: {
        totalCodeExamples: enhancedResults.length,
        totalDocumentation: documentationResults.length,
      },
    };
  }
  
  private detectCodeType(url: string): string {
    if (url.includes('github.com')) return 'repository';
    if (url.includes('stackoverflow.com')) return 'qa';
    if (url.includes('dev.to') || url.includes('medium.com')) return 'article';
    return 'other';
  }
  
  private detectLanguage(content: string): string | null {
    // Simple language detection based on keywords
    const languageIndicators = {
      javascript: ['const', 'let', 'var', 'function', '=>', 'async', 'await'],
      python: ['def', 'import', 'from', '__init__', 'self', 'print('],
      java: ['public class', 'private', 'void', 'System.out', 'import java'],
      typescript: ['interface', 'type', 'implements', ': string', ': number'],
      rust: ['fn', 'let mut', 'impl', 'struct', 'enum', '::'],
      go: ['func', 'package', 'import (', 'fmt.', 'err :='],
    };
    
    for (const [lang, indicators] of Object.entries(languageIndicators)) {
      if (indicators.some(indicator => content.includes(indicator))) {
        return lang;
      }
    }
    
    return null;
  }
  
  private async researchAssistant(args: unknown) {
    const params = z.object({
      topic: z.string(),
      questions: z.array(z.string()).optional(),
      depth: z.enum(['quick', 'standard', 'comprehensive']).optional().default('standard'),
      sources: z.array(z.string()).optional(),
    }).parse(args);
    
    const research = {
      topic: params.topic,
      findings: [] as any[],
      summary: '',
      questions: params.questions || [],
      sources: [] as any[],
    };
    
    // Determine search depth based on research depth
    const searchDepth = params.depth === 'comprehensive' ? 'advanced' : 'basic';
    const maxResults = params.depth === 'quick' ? 5 : params.depth === 'comprehensive' ? 20 : 10;
    
    // Initial topic search
    const topicSearch = await this.webSearch({
      query: params.topic,
      searchEngine: 'all',
      maxResults,
      searchDepth,
      includeAnswer: true,
    });
    
    research.findings.push({
      type: 'overview',
      content: topicSearch.answer || 'No overview available',
      sources: topicSearch.results.slice(0, 5),
    });
    
    // Search for specific questions
    if (params.questions && params.questions.length > 0) {
      for (const question of params.questions) {
        const questionSearch = await this.webSearch({
          query: `${params.topic} ${question}`,
          searchEngine: 'all',
          maxResults: 5,
          searchDepth: 'basic',
          includeAnswer: true,
        });
        
        research.findings.push({
          type: 'question',
          question,
          answer: questionSearch.answer || 'No specific answer found',
          sources: questionSearch.results.slice(0, 3),
        });
      }
    }
    
    // Search preferred sources if specified
    if (params.sources && params.sources.length > 0) {
      for (const source of params.sources) {
        const sourceSearch = await this.webSearch({
          query: `${params.topic} site:${source}`,
          searchEngine: 'all',
          maxResults: 3,
          searchDepth: 'basic',
        });
        
        if (sourceSearch.results.length > 0) {
          research.sources.push({
            domain: source,
            results: sourceSearch.results,
          });
        }
      }
    }
    
    // Generate comprehensive summary
    research.summary = this.generateResearchSummary(research);
    
    return research;
  }
  
  private generateResearchSummary(research: any): string {
    let summary = `Research on "${research.topic}"\\n\\n`;
    
    // Add overview
    const overview = research.findings.find((f: any) => f.type === 'overview');
    if (overview) {
      summary += `Overview:\\n${overview.content}\\n\\n`;
    }
    
    // Add question answers
    const questions = research.findings.filter((f: any) => f.type === 'question');
    if (questions.length > 0) {
      summary += 'Key Findings:\\n';
      questions.forEach((q: any) => {
        summary += `\\nQ: ${q.question}\\nA: ${q.answer}\\n`;
      });
    }
    
    // Add source summary
    if (research.sources.length > 0) {
      summary += '\\nSources consulted:\\n';
      research.sources.forEach((s: any) => {
        summary += `- ${s.domain}: ${s.results.length} relevant articles found\\n`;
      });
    }
    
    return summary;
  }
  
  private async realtimeInfo(args: unknown) {
    const params = z.object({
      infoType: z.enum(['news', 'weather', 'stocks', 'sports', 'crypto']),
      query: z.string(),
      timeframe: z.enum(['latest', 'today', 'week', 'month']).optional().default('latest'),
    }).parse(args);
    
    let searchQuery = '';
    let searchType = 'web';
    
    switch (params.infoType) {
      case 'news':
        searchQuery = `${params.query} news ${params.timeframe}`;
        searchType = 'news';
        break;
      case 'weather':
        searchQuery = `weather ${params.query} current forecast`;
        break;
      case 'stocks':
        searchQuery = `${params.query} stock price quote market ${params.timeframe}`;
        break;
      case 'sports':
        searchQuery = `${params.query} sports scores results ${params.timeframe}`;
        searchType = 'news';
        break;
      case 'crypto':
        searchQuery = `${params.query} cryptocurrency price market cap ${params.timeframe}`;
        break;
    }
    
    const results = await this.webSearch({
      query: searchQuery,
      searchEngine: 'all',
      maxResults: 10,
      searchDepth: 'basic',
      includeAnswer: true,
      searchType: searchType as any,
    });
    
    return {
      infoType: params.infoType,
      query: params.query,
      timeframe: params.timeframe,
      data: results.answer || 'No real-time data available',
      sources: results.results.slice(0, 5),
      lastUpdated: new Date().toISOString(),
    };
  }
  
  // Abstract method implementations
  protected async setupResources(): Promise<void> {
    // Search Integration server doesn't need resources
    this.logger.info('Search Integration server: No resources to setup');
  }
  
  protected async readResource(uri: string): Promise<{ uri: string; mimeType?: string; text?: string; blob?: string }> {
    throw new Error(`Resource not found: ${uri}`);
  }
  
  protected async cleanup(): Promise<void> {
    this.logger.info('Search Integration server cleanup completed');
  }
}

// Start the server if this file is run directly
if (require.main === module) {
  const server = new SearchIntegrationServer();
  server.start().catch(console.error);
}