declare module '@smithery/sdk' {
  export interface SmitheryConfig {
    apiKey: string;
  }

  export interface SmitheryResponse {
    text: string;
    result?: string;
    metadata?: Record<string, any>;
  }

  export interface ForgeOptions {
    prompt: string;
    model?: string;
    temperature?: number;
    max_tokens?: number;
    [key: string]: any;
  }

  export class Smithery {
    constructor(config: SmitheryConfig);
    
    enhance(input: {
      text: string;
      type: string;
      options?: Record<string, any>;
    }): Promise<SmitheryResponse>;
    
    generate(input: {
      prompt: string;
      options?: Record<string, any>;
    }): Promise<SmitheryResponse>;
    
    analyze(input: {
      content: string;
      type: string;
      options?: Record<string, any>;
    }): Promise<SmitheryResponse>;
    
    forge(options: ForgeOptions): Promise<SmitheryResponse>;
  }
}