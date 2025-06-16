import { BaseMCPServer } from '../../core/base-server';
import { z } from 'zod';
import { Smithery } from '@smithery/sdk';
import { config } from '../../core/config';

// Schema definitions
const TextEnhancementSchema = z.object({
  text: z.string(),
  enhancementType: z.enum(['grammar', 'clarity', 'conciseness', 'tone', 'all']),
  targetTone: z.enum(['professional', 'casual', 'academic', 'creative']).optional(),
  preserveStyle: z.boolean().optional().default(true),
});

const CodeEnhancementSchema = z.object({
  code: z.string(),
  language: z.string(),
  enhancementType: z.enum(['optimize', 'refactor', 'document', 'test', 'security']),
  context: z.string().optional(),
  preserveFunctionality: z.boolean().optional().default(true),
});

const IdeaGenerationSchema = z.object({
  prompt: z.string(),
  domain: z.enum(['business', 'technical', 'creative', 'research', 'general']),
  numberOfIdeas: z.number().optional().default(5),
  constraints: z.array(z.string()).optional(),
  targetAudience: z.string().optional(),
});

const ProblemSolvingSchema = z.object({
  problem: z.string(),
  context: z.string().optional(),
  constraints: z.array(z.string()).optional(),
  preferredApproach: z.enum(['analytical', 'creative', 'systematic', 'innovative']).optional(),
  includeSteps: z.boolean().optional().default(true),
});

export class AIEnhancementServer extends BaseMCPServer {
  private smithery: Smithery;
  
  constructor() {
    super({
      name: 'ai-enhancement',
      version: '1.0.0',
      description: 'MCP server for AI-powered enhancements using Smithery',
    });
    
    this.smithery = new Smithery({
      apiKey: config.smithery.apiKey,
    });
  }
  
  protected async setupTools(): Promise<void> {
    // Tool: Text Enhancement
    this.registerTool({
      name: 'enhance_text',
      description: 'Enhance text for grammar, clarity, tone, and style',
      inputSchema: {
        type: 'object',
        properties: {
          text: { type: 'string', description: 'Text to enhance' },
          enhancementType: {
            type: 'string',
            enum: ['grammar', 'clarity', 'conciseness', 'tone', 'all'],
            description: 'Type of enhancement'
          },
          targetTone: {
            type: 'string',
            enum: ['professional', 'casual', 'academic', 'creative'],
            description: 'Target tone (optional)'
          },
          preserveStyle: {
            type: 'boolean',
            description: 'Preserve original writing style (default: true)'
          },
        },
        required: ['text', 'enhancementType'],
      },
    });
    
    // Tool: Code Enhancement
    this.registerTool({
      name: 'enhance_code',
      description: 'Enhance code through optimization, refactoring, documentation, or security improvements',
      inputSchema: {
        type: 'object',
        properties: {
          code: { type: 'string', description: 'Code to enhance' },
          language: { type: 'string', description: 'Programming language' },
          enhancementType: {
            type: 'string',
            enum: ['optimize', 'refactor', 'document', 'test', 'security'],
            description: 'Type of enhancement'
          },
          context: { type: 'string', description: 'Additional context about the code' },
          preserveFunctionality: {
            type: 'boolean',
            description: 'Ensure functionality remains unchanged (default: true)'
          },
        },
        required: ['code', 'language', 'enhancementType'],
      },
    });
    
    // Tool: Idea Generation
    this.registerTool({
      name: 'generate_ideas',
      description: 'Generate creative ideas based on prompts and constraints',
      inputSchema: {
        type: 'object',
        properties: {
          prompt: { type: 'string', description: 'Idea generation prompt' },
          domain: {
            type: 'string',
            enum: ['business', 'technical', 'creative', 'research', 'general'],
            description: 'Domain for idea generation'
          },
          numberOfIdeas: {
            type: 'number',
            description: 'Number of ideas to generate (default: 5)'
          },
          constraints: {
            type: 'array',
            items: { type: 'string' },
            description: 'Constraints or requirements'
          },
          targetAudience: {
            type: 'string',
            description: 'Target audience for the ideas'
          },
        },
        required: ['prompt', 'domain'],
      },
    });
    
    // Tool: Problem Solving Assistant
    this.registerTool({
      name: 'solve_problem',
      description: 'Provide structured problem-solving assistance',
      inputSchema: {
        type: 'object',
        properties: {
          problem: { type: 'string', description: 'Problem description' },
          context: { type: 'string', description: 'Additional context' },
          constraints: {
            type: 'array',
            items: { type: 'string' },
            description: 'Constraints or limitations'
          },
          preferredApproach: {
            type: 'string',
            enum: ['analytical', 'creative', 'systematic', 'innovative'],
            description: 'Preferred problem-solving approach'
          },
          includeSteps: {
            type: 'boolean',
            description: 'Include step-by-step solution (default: true)'
          },
        },
        required: ['problem'],
      },
    });
    
    // Tool: Learning Assistant
    this.registerTool({
      name: 'learning_assistant',
      description: 'Create personalized learning materials and explanations',
      inputSchema: {
        type: 'object',
        properties: {
          topic: { type: 'string', description: 'Topic to learn' },
          currentLevel: {
            type: 'string',
            enum: ['beginner', 'intermediate', 'advanced', 'expert'],
            description: 'Current knowledge level'
          },
          learningStyle: {
            type: 'string',
            enum: ['visual', 'verbal', 'practical', 'theoretical'],
            description: 'Preferred learning style'
          },
          timeAvailable: {
            type: 'string',
            enum: ['5min', '15min', '30min', '1hour', 'extended'],
            description: 'Time available for learning'
          },
          includeExamples: {
            type: 'boolean',
            description: 'Include practical examples (default: true)'
          },
        },
        required: ['topic', 'currentLevel'],
      },
    });
  }
  
  protected async executeTool(name: string, args: unknown): Promise<unknown> {
    switch (name) {
      case 'enhance_text':
        return this.enhanceText(args);
      case 'enhance_code':
        return this.enhanceCode(args);
      case 'generate_ideas':
        return this.generateIdeas(args);
      case 'solve_problem':
        return this.solveProblem(args);
      case 'learning_assistant':
        return this.learningAssistant(args);
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }
  
  private async enhanceText(args: unknown) {
    const params = TextEnhancementSchema.parse(args);
    
    try {
      const enhancements: any = {
        original: params.text,
        enhanced: '',
        changes: [],
        metrics: {},
      };
      
      // Use Smithery API for text enhancement
      const prompt = this.buildTextEnhancementPrompt(params);
      const response = await this.smithery.forge({
        prompt,
        model: 'claude-3-opus',
        temperature: 0.3,
        max_tokens: 2000,
      });
      
      // Parse the enhanced text and changes
      const result = this.parseEnhancementResponse(response.text);
      enhancements.enhanced = result.enhanced;
      enhancements.changes = result.changes;
      
      // Calculate improvement metrics
      enhancements.metrics = this.calculateTextMetrics(
        params.text,
        enhancements.enhanced
      );
      
      return enhancements;
    } catch (error) {
      this.logger.error({ error }, 'Text enhancement failed');
      throw error;
    }
  }
  
  private buildTextEnhancementPrompt(params: any): string {
    let prompt = `Please enhance the following text focusing on ${params.enhancementType}.\\n\\n`;
    
    if (params.targetTone) {
      prompt += `Target tone: ${params.targetTone}\\n`;
    }
    
    if (params.preserveStyle) {
      prompt += `Important: Preserve the original writing style and voice.\\n`;
    }
    
    prompt += `\\nOriginal text:\\n${params.text}\\n\\n`;
    prompt += `Please provide:\\n1. The enhanced text\\n2. A list of key changes made\\n3. Explanation of improvements`;
    
    return prompt;
  }
  
  private parseEnhancementResponse(response: string): any {
    // Parse the AI response to extract enhanced text and changes
    // This is a simplified version - in production, use more robust parsing
    const sections = response.split('\\n\\n');
    
    return {
      enhanced: sections[0] || response,
      changes: this.extractChanges(response),
    };
  }
  
  private extractChanges(response: string): string[] {
    // Extract bullet points or numbered lists of changes
    const changePatterns = [
      /^[-•*]\s+(.+)$/gm,
      /^\d+\.\s+(.+)$/gm,
    ];
    
    const changes: string[] = [];
    for (const pattern of changePatterns) {
      const matches = response.matchAll(pattern);
      for (const match of matches) {
        changes.push(match[1]);
      }
    }
    
    return changes;
  }
  
  private calculateTextMetrics(original: string, enhanced: string): any {
    const originalWords = original.split(/\s+/).length;
    const enhancedWords = enhanced.split(/\s+/).length;
    const originalSentences = original.split(/[.!?]+/).length - 1;
    const enhancedSentences = enhanced.split(/[.!?]+/).length - 1;
    
    return {
      wordCount: {
        original: originalWords,
        enhanced: enhancedWords,
        change: enhancedWords - originalWords,
      },
      sentenceCount: {
        original: originalSentences,
        enhanced: enhancedSentences,
        change: enhancedSentences - originalSentences,
      },
      averageWordLength: {
        original: original.replace(/\s+/g, '').length / originalWords,
        enhanced: enhanced.replace(/\s+/g, '').length / enhancedWords,
      },
      readabilityImprovement: this.estimateReadabilityImprovement(original, enhanced),
    };
  }
  
  private estimateReadabilityImprovement(original: string, enhanced: string): string {
    // Simplified readability estimation
    const originalComplexity = this.textComplexity(original);
    const enhancedComplexity = this.textComplexity(enhanced);
    
    if (enhancedComplexity < originalComplexity) {
      return 'Improved (simpler)';
    } else if (enhancedComplexity > originalComplexity) {
      return 'More sophisticated';
    }
    return 'Similar complexity';
  }
  
  private textComplexity(text: string): number {
    const words = text.split(/\s+/);
    const avgWordLength = text.replace(/\s+/g, '').length / words.length;
    const avgSentenceLength = words.length / (text.split(/[.!?]+/).length - 1);
    return avgWordLength * 0.5 + avgSentenceLength * 0.5;
  }
  
  private async enhanceCode(args: unknown) {
    const params = CodeEnhancementSchema.parse(args);
    
    try {
      const prompt = this.buildCodeEnhancementPrompt(params);
      const response = await this.smithery.forge({
        prompt,
        model: 'claude-3-opus',
        temperature: 0.2,
        max_tokens: 3000,
      });
      
      const result = this.parseCodeEnhancementResponse(response.text, params);
      
      return {
        original: params.code,
        enhanced: result.enhancedCode,
        improvements: result.improvements,
        explanation: result.explanation,
        language: params.language,
        enhancementType: params.enhancementType,
      };
    } catch (error) {
      this.logger.error({ error }, 'Code enhancement failed');
      throw error;
    }
  }
  
  private buildCodeEnhancementPrompt(params: any): string {
    let prompt = `Please enhance the following ${params.language} code by focusing on ${params.enhancementType}.\\n\\n`;
    
    if (params.context) {
      prompt += `Context: ${params.context}\\n\\n`;
    }
    
    if (params.preserveFunctionality) {
      prompt += `Important: The functionality must remain exactly the same.\\n\\n`;
    }
    
    prompt += `Original code:\\n\`\`\`${params.language}\\n${params.code}\\n\`\`\`\\n\\n`;
    
    switch (params.enhancementType) {
      case 'optimize':
        prompt += 'Please optimize for performance, focusing on time and space complexity.';
        break;
      case 'refactor':
        prompt += 'Please refactor for better readability, maintainability, and adherence to best practices.';
        break;
      case 'document':
        prompt += 'Please add comprehensive documentation, including function docstrings and inline comments.';
        break;
      case 'test':
        prompt += 'Please create comprehensive unit tests for this code.';
        break;
      case 'security':
        prompt += 'Please identify and fix security vulnerabilities, and add security best practices.';
        break;
    }
    
    prompt += '\\n\\nProvide:\\n1. The enhanced code\\n2. List of improvements made\\n3. Explanation of changes';
    
    return prompt;
  }
  
  private parseCodeEnhancementResponse(response: string, params: any): any {
    // Extract code blocks
    const codeBlockRegex = new RegExp(`\`\`\`${params.language}?\\n([\\s\\S]*?)\`\`\``, 'g');
    const codeBlocks = Array.from(response.matchAll(codeBlockRegex));
    
    const enhancedCode = codeBlocks[0]?.[1] || params.code;
    
    // Extract improvements and explanation
    const improvements = this.extractChanges(response);
    const explanation = response.split('\\n\\n')
      .filter(section => !section.includes('```') && section.length > 50)
      .join('\\n\\n');
    
    return {
      enhancedCode,
      improvements,
      explanation,
    };
  }
  
  private async generateIdeas(args: unknown) {
    const params = IdeaGenerationSchema.parse(args);
    
    try {
      const prompt = this.buildIdeaGenerationPrompt(params);
      const response = await this.smithery.forge({
        prompt,
        model: 'claude-3-opus',
        temperature: 0.8,
        max_tokens: 2000,
      });
      
      const ideas = this.parseIdeasResponse(response.text, params.numberOfIdeas);
      
      return {
        prompt: params.prompt,
        domain: params.domain,
        ideas: ideas,
        metadata: {
          totalIdeas: ideas.length,
          constraints: params.constraints || [],
          targetAudience: params.targetAudience || 'general',
        },
      };
    } catch (error) {
      this.logger.error({ error }, 'Idea generation failed');
      throw error;
    }
  }
  
  private buildIdeaGenerationPrompt(params: any): string {
    let prompt = `Generate ${params.numberOfIdeas} innovative ideas for the following prompt in the ${params.domain} domain:\\n\\n`;
    prompt += `Prompt: ${params.prompt}\\n\\n`;
    
    if (params.constraints && params.constraints.length > 0) {
      prompt += `Constraints:\\n`;
      params.constraints.forEach((c: string) => {
        prompt += `- ${c}\\n`;
      });
      prompt += '\\n';
    }
    
    if (params.targetAudience) {
      prompt += `Target Audience: ${params.targetAudience}\\n\\n`;
    }
    
    prompt += `Please provide ${params.numberOfIdeas} distinct, creative, and actionable ideas. For each idea, include:\\n`;
    prompt += '1. A clear title\\n';
    prompt += '2. Brief description (2-3 sentences)\\n';
    prompt += '3. Key benefits\\n';
    prompt += '4. Implementation considerations\\n';
    
    return prompt;
  }
  
  private parseIdeasResponse(response: string, expectedCount: number): any[] {
    const ideas: any[] = [];
    
    // Try to parse numbered ideas
    const ideaSections = response.split(/\d+\.\s+/);
    
    for (let i = 1; i < ideaSections.length && ideas.length < expectedCount; i++) {
      const section = ideaSections[i];
      const lines = section.split('\\n').filter(l => l.trim());
      
      if (lines.length > 0) {
        const idea = {
          id: i,
          title: lines[0],
          description: '',
          benefits: [] as string[],
          implementation: [] as string[],
        };
        
        // Parse the rest of the content
        let currentSectionType = '';
        for (const line of lines.slice(1)) {
          if (line.toLowerCase().includes('description:')) {
            currentSectionType = 'description';
          } else if (line.toLowerCase().includes('benefit')) {
            currentSectionType = 'benefits';
          } else if (line.toLowerCase().includes('implementation')) {
            currentSectionType = 'implementation';
          } else if (currentSectionType === 'description') {
            idea.description += line + ' ';
          } else if (currentSectionType === 'benefits') {
            idea.benefits.push(line.replace(/^[-•*]\s*/, ''));
          } else if (currentSectionType === 'implementation') {
            idea.implementation.push(line.replace(/^[-•*]\s*/, ''));
          }
        }
        
        ideas.push(idea);
      }
    }
    
    return ideas;
  }
  
  private async solveProblem(args: unknown) {
    const params = ProblemSolvingSchema.parse(args);
    
    try {
      const prompt = this.buildProblemSolvingPrompt(params);
      const response = await this.smithery.forge({
        prompt,
        model: 'claude-3-opus',
        temperature: 0.4,
        max_tokens: 2500,
      });
      
      const solution = this.parseProblemSolution(response.text, params);
      
      return {
        problem: params.problem,
        solution: solution.solution,
        steps: solution.steps,
        alternativeApproaches: solution.alternatives,
        considerations: solution.considerations,
        approach: params.preferredApproach || 'systematic',
      };
    } catch (error) {
      this.logger.error({ error }, 'Problem solving failed');
      throw error;
    }
  }
  
  private buildProblemSolvingPrompt(params: any): string {
    let prompt = 'Please help solve the following problem using a ';
    prompt += params.preferredApproach || 'systematic';
    prompt += ' approach:\\n\\n';
    
    prompt += `Problem: ${params.problem}\\n\\n`;
    
    if (params.context) {
      prompt += `Context: ${params.context}\\n\\n`;
    }
    
    if (params.constraints && params.constraints.length > 0) {
      prompt += 'Constraints:\\n';
      params.constraints.forEach((c: string) => {
        prompt += `- ${c}\\n`;
      });
      prompt += '\\n';
    }
    
    prompt += 'Please provide:\\n';
    prompt += '1. A clear solution to the problem\\n';
    if (params.includeSteps) {
      prompt += '2. Step-by-step instructions to implement the solution\\n';
    }
    prompt += '3. Alternative approaches (at least 2)\\n';
    prompt += '4. Important considerations and potential pitfalls\\n';
    
    return prompt;
  }
  
  private parseProblemSolution(response: string, params: any): any {
    const sections = response.split('\\n\\n');
    
    const solution = {
      solution: '',
      steps: [] as string[],
      alternatives: [] as string[],
      considerations: [] as string[],
    };
    
    // Parse solution sections
    
    for (const section of sections) {
      const lowerSection = section.toLowerCase();
      
      if (lowerSection.includes('solution:') || sections.indexOf(section) === 0) {
        solution.solution = section.replace(/^solution:\s*/i, '');
      } else if (lowerSection.includes('step') && params.includeSteps) {
        const steps = section.split('\\n').filter(l => l.match(/^\d+\.|^[-•*]/));
        solution.steps = steps.map(s => s.replace(/^\d+\.\s*|^[-•*]\s*/, ''));
      } else if (lowerSection.includes('alternative')) {
        const alts = section.split('\\n').filter(l => l.trim());
        solution.alternatives = alts.slice(1); // Skip the header
      } else if (lowerSection.includes('consideration') || lowerSection.includes('pitfall')) {
        const considerations = section.split('\\n').filter(l => l.match(/^[-•*]/));
        solution.considerations = considerations.map(c => c.replace(/^[-•*]\s*/, ''));
      }
    }
    
    return solution;
  }
  
  private async learningAssistant(args: unknown) {
    const params = z.object({
      topic: z.string(),
      currentLevel: z.enum(['beginner', 'intermediate', 'advanced', 'expert']),
      learningStyle: z.enum(['visual', 'verbal', 'practical', 'theoretical']).optional(),
      timeAvailable: z.enum(['5min', '15min', '30min', '1hour', 'extended']).optional(),
      includeExamples: z.boolean().optional().default(true),
    }).parse(args);
    
    try {
      const prompt = this.buildLearningPrompt(params);
      const response = await this.smithery.forge({
        prompt,
        model: 'claude-3-opus',
        temperature: 0.5,
        max_tokens: 3000,
      });
      
      const learningPlan = this.parseLearningResponse(response.text, params);
      
      return {
        topic: params.topic,
        level: params.currentLevel,
        learningPlan: learningPlan,
        estimatedTime: params.timeAvailable || '30min',
        nextSteps: this.generateNextSteps(params.topic, params.currentLevel),
      };
    } catch (error) {
      this.logger.error({ error }, 'Learning assistant failed');
      throw error;
    }
  }
  
  private buildLearningPrompt(params: any): string {
    let prompt = `Create a learning plan for "${params.topic}" tailored for a ${params.currentLevel} learner.\\n\\n`;
    
    if (params.learningStyle) {
      prompt += `Learning style preference: ${params.learningStyle}\\n`;
    }
    
    if (params.timeAvailable) {
      prompt += `Time available: ${params.timeAvailable}\\n`;
    }
    
    prompt += '\\nPlease provide:\\n';
    prompt += '1. A clear overview of the topic\\n';
    prompt += '2. Key concepts to understand\\n';
    prompt += '3. Learning objectives\\n';
    
    if (params.includeExamples) {
      prompt += '4. Practical examples and exercises\\n';
    }
    
    prompt += '5. Resources for further learning\\n';
    
    if (params.learningStyle === 'visual') {
      prompt += '\\nInclude visual representations and diagrams where helpful.';
    } else if (params.learningStyle === 'practical') {
      prompt += '\\nFocus on hands-on exercises and real-world applications.';
    }
    
    return prompt;
  }
  
  private parseLearningResponse(response: string, params: any): any {
    return {
      overview: this.extractSection(response, 'overview'),
      keyConcepts: this.extractListItems(response, 'key concepts'),
      objectives: this.extractListItems(response, 'objectives'),
      examples: params.includeExamples ? this.extractExamples(response) : [],
      resources: this.extractResources(response),
      summary: this.generateLearningSummary(response),
    };
  }
  
  private extractSection(text: string, sectionName: string): string {
    const regex = new RegExp(`${sectionName}:?\\s*([^\\n]+(?:\\n(?!\\n)[^\\n]+)*)`, 'i');
    const match = text.match(regex);
    return match ? match[1].trim() : '';
  }
  
  private extractListItems(text: string, sectionName: string): string[] {
    const sectionRegex = new RegExp(`${sectionName}:?\\s*\\n([\\s\\S]*?)(?=\\n\\n|$)`, 'i');
    const sectionMatch = text.match(sectionRegex);
    
    if (!sectionMatch) return [];
    
    const items = sectionMatch[1].split('\\n')
      .filter(line => line.match(/^[-•*]|^\d+\./))
      .map(line => line.replace(/^[-•*]\s*|^\d+\.\s*/, '').trim());
    
    return items;
  }
  
  private extractExamples(text: string): any[] {
    const examples: any[] = [];
    const exampleRegex = /example\s*\d*:?\s*([\s\S]*?)(?=example\s*\d*:|$)/gi;
    const matches = Array.from(text.matchAll(exampleRegex));
    
    for (const match of matches) {
      examples.push({
        content: match[1].trim(),
        type: this.detectExampleType(match[1]),
      });
    }
    
    return examples;
  }
  
  private detectExampleType(content: string): string {
    if (content.includes('```')) return 'code';
    if (content.match(/^\d+\.|^[-•*]/m)) return 'list';
    if (content.includes('?')) return 'question';
    return 'text';
  }
  
  private extractResources(text: string): any[] {
    const resources: any[] = [];
    const resourceSection = text.match(/resources?:?\s*([\s\S]*?)(?=\n\n|$)/i);
    
    if (resourceSection) {
      const lines = resourceSection[1].split('\\n').filter(l => l.trim());
      for (const line of lines) {
        if (line.match(/^[-•*]|^\d+\./)) {
          const cleanLine = line.replace(/^[-•*]\s*|^\d+\.\s*/, '');
          resources.push({
            title: cleanLine,
            type: this.detectResourceType(cleanLine),
          });
        }
      }
    }
    
    return resources;
  }
  
  private detectResourceType(resource: string): string {
    if (resource.toLowerCase().includes('book')) return 'book';
    if (resource.toLowerCase().includes('video')) return 'video';
    if (resource.toLowerCase().includes('course')) return 'course';
    if (resource.includes('http')) return 'website';
    return 'other';
  }
  
  private generateLearningSummary(response: string): string {
    // Extract key points for a summary
    const lines = response.split('\\n').filter(l => l.trim());
    const keyPoints = lines
      .filter(l => l.length > 50 && l.length < 200)
      .slice(0, 3)
      .join(' ');
    
    return keyPoints || 'Complete the learning plan above to master this topic.';
  }
  
  private generateNextSteps(topic: string, level: string): string[] {
    const nextLevel = {
      'beginner': 'intermediate',
      'intermediate': 'advanced',
      'advanced': 'expert',
      'expert': 'expert',
    }[level];
    
    return [
      `Practice the concepts learned in ${topic}`,
      `Apply knowledge to real-world projects`,
      `Explore related topics and connections`,
      `Progress to ${nextLevel} level materials`,
      'Share knowledge with others or teach',
    ];
  }
  
  // Abstract method implementations
  protected async setupResources(): Promise<void> {
    // AI Enhancement server doesn't need resources
    this.logger.info('AI Enhancement server: No resources to setup');
  }
  
  protected async readResource(uri: string): Promise<{ uri: string; mimeType?: string; text?: string; blob?: string }> {
    throw new Error(`Resource not found: ${uri}`);
  }
  
  protected async cleanup(): Promise<void> {
    this.logger.info('AI Enhancement server cleanup completed');
  }
}

// Start the server if this file is run directly
if (require.main === module) {
  const server = new AIEnhancementServer();
  server.start().catch(console.error);
}