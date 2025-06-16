import { BaseMCPServer } from '../../core/base-server';
import { z } from 'zod';
import fs from 'fs/promises';
import path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

// Schema definitions for tool parameters
const CreateProjectSchema = z.object({
  projectName: z.string(),
  template: z.enum(['fastapi', 'express', 'react', 'vue', 'django', 'flask']),
  features: z.array(z.string()).optional(),
  directory: z.string().optional(),
});

const RunCommandSchema = z.object({
  command: z.string(),
  cwd: z.string().optional(),
  env: z.record(z.string()).optional(),
});

const GenerateBoilerplateSchema = z.object({
  type: z.enum(['component', 'service', 'test', 'api-endpoint', 'model']),
  name: z.string(),
  directory: z.string(),
  options: z.record(z.any()).optional(),
});

export class DevelopmentWorkflowServer extends BaseMCPServer {
  constructor() {
    super({
      name: 'development-workflow',
      version: '1.0.0',
      description: 'MCP server for development workflow automation',
    });
  }
  
  protected async setupTools(): Promise<void> {
    // Tool: Create Project Structure
    this.registerTool({
      name: 'create_project_structure',
      description: 'Create a new project with the specified template and features',
      inputSchema: {
        type: 'object',
        properties: {
          projectName: { type: 'string', description: 'Name of the project' },
          template: { 
            type: 'string', 
            enum: ['fastapi', 'express', 'react', 'vue', 'django', 'flask'],
            description: 'Project template to use' 
          },
          features: { 
            type: 'array', 
            items: { type: 'string' },
            description: 'Additional features to include' 
          },
          directory: { type: 'string', description: 'Target directory (optional)' },
        },
        required: ['projectName', 'template'],
      },
    });
    
    // Tool: Run Development Command
    this.registerTool({
      name: 'run_dev_command',
      description: 'Execute a development command (npm, pip, etc.)',
      inputSchema: {
        type: 'object',
        properties: {
          command: { type: 'string', description: 'Command to execute' },
          cwd: { type: 'string', description: 'Working directory' },
          env: { 
            type: 'object', 
            additionalProperties: { type: 'string' },
            description: 'Environment variables' 
          },
        },
        required: ['command'],
      },
    });
    
    // Tool: Generate Boilerplate Code
    this.registerTool({
      name: 'generate_boilerplate',
      description: 'Generate boilerplate code for components, services, tests, etc.',
      inputSchema: {
        type: 'object',
        properties: {
          type: { 
            type: 'string',
            enum: ['component', 'service', 'test', 'api-endpoint', 'model'],
            description: 'Type of boilerplate to generate' 
          },
          name: { type: 'string', description: 'Name of the item' },
          directory: { type: 'string', description: 'Target directory' },
          options: { 
            type: 'object',
            description: 'Additional options specific to the type' 
          },
        },
        required: ['type', 'name', 'directory'],
      },
    });
    
    // Tool: Setup Development Environment
    this.registerTool({
      name: 'setup_dev_environment',
      description: 'Set up development environment with necessary tools and dependencies',
      inputSchema: {
        type: 'object',
        properties: {
          projectPath: { type: 'string', description: 'Path to the project' },
          environment: { 
            type: 'string',
            enum: ['node', 'python', 'java', 'go', 'rust'],
            description: 'Development environment type' 
          },
          installDependencies: { 
            type: 'boolean',
            description: 'Whether to install dependencies' 
          },
        },
        required: ['projectPath', 'environment'],
      },
    });
  }
  
  protected async executeTool(name: string, args: unknown): Promise<unknown> {
    switch (name) {
      case 'create_project_structure':
        return this.createProjectStructure(args);
      case 'run_dev_command':
        return this.runDevCommand(args);
      case 'generate_boilerplate':
        return this.generateBoilerplate(args);
      case 'setup_dev_environment':
        return this.setupDevEnvironment(args);
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }
  
  private async createProjectStructure(args: unknown) {
    const params = CreateProjectSchema.parse(args);
    const projectDir = path.join(
      params.directory || process.cwd(),
      params.projectName
    );
    
    // Create project directory
    await fs.mkdir(projectDir, { recursive: true });
    
    // Generate project structure based on template
    const files: string[] = [];
    
    switch (params.template) {
      case 'fastapi':
        files.push(
          ...(await this.createFastAPIProject(projectDir, params.features || []))
        );
        break;
      case 'express':
        files.push(
          ...(await this.createExpressProject(projectDir, params.features || []))
        );
        break;
      case 'react':
        files.push(
          ...(await this.createReactProject(projectDir, params.features || []))
        );
        break;
      // Add more templates as needed
      default:
        throw new Error(`Template ${params.template} not implemented yet`);
    }
    
    return {
      success: true,
      projectPath: projectDir,
      filesCreated: files,
      nextSteps: this.getNextSteps(params.template),
    };
  }
  
  private async createFastAPIProject(projectDir: string, features: string[]) {
    const files: string[] = [];
    
    // Main application file
    const mainPy = `from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="My FastAPI App")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}
`;
    
    await fs.writeFile(path.join(projectDir, 'main.py'), mainPy);
    files.push('main.py');
    
    // Requirements file
    const requirements = `fastapi==0.104.1
uvicorn==0.24.0
pydantic==2.5.0
${features.includes('database') ? 'sqlalchemy==2.0.23\\nalembic==1.12.1' : ''}
${features.includes('auth') ? 'python-jose[cryptography]==3.3.0\\npasslib[bcrypt]==1.7.4' : ''}
${features.includes('tests') ? 'pytest==7.4.3\\npytest-asyncio==0.21.1\\nhttpx==0.25.2' : ''}
`.trim();
    
    await fs.writeFile(path.join(projectDir, 'requirements.txt'), requirements);
    files.push('requirements.txt');
    
    // Create additional directories
    if (features.includes('tests')) {
      await fs.mkdir(path.join(projectDir, 'tests'), { recursive: true });
      const testMain = `import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Hello World"}

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}
`;
      await fs.writeFile(path.join(projectDir, 'tests', 'test_main.py'), testMain);
      files.push('tests/test_main.py');
    }
    
    return files;
  }
  
  private async createExpressProject(projectDir: string, features: string[]) {
    const files: string[] = [];
    
    // Package.json
    const packageJson = {
      name: path.basename(projectDir),
      version: '1.0.0',
      description: 'Express.js application',
      main: 'src/index.js',
      scripts: {
        start: 'node src/index.js',
        dev: 'nodemon src/index.js',
        test: features.includes('tests') ? 'jest' : 'echo "No tests"',
      },
      dependencies: {
        express: '^4.18.2',
        'cors': '^2.8.5',
        'helmet': '^7.1.0',
        ...(features.includes('database') && { 
          'mongoose': '^8.0.0',
          'dotenv': '^16.3.1',
        }),
        ...(features.includes('auth') && {
          'jsonwebtoken': '^9.0.2',
          'bcryptjs': '^2.4.3',
        }),
      },
      devDependencies: {
        nodemon: '^3.0.1',
        ...(features.includes('tests') && {
          jest: '^29.7.0',
          supertest: '^6.3.3',
        }),
      },
    };
    
    await fs.writeFile(
      path.join(projectDir, 'package.json'),
      JSON.stringify(packageJson, null, 2)
    );
    files.push('package.json');
    
    // Create src directory
    await fs.mkdir(path.join(projectDir, 'src'), { recursive: true });
    
    // Main server file
    const indexJs = `const express = require('express');
const cors = require('cors');
const helmet = require('helmet');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Routes
app.get('/', (req, res) => {
  res.json({ message: 'Hello World' });
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy' });
});

// Start server
app.listen(PORT, () => {
  console.log(\`Server running on port \${PORT}\`);
});

module.exports = app;
`;
    
    await fs.writeFile(path.join(projectDir, 'src', 'index.js'), indexJs);
    files.push('src/index.js');
    
    return files;
  }
  
  private async createReactProject(projectDir: string, _features: string[]) {
    // For React, we'll use create-react-app or vite
    const { stdout } = await execAsync(
      `npx create-react-app ${path.basename(projectDir)} --template typescript`,
      { cwd: path.dirname(projectDir) }
    );
    
    this.logger.info({ stdout }, 'React project created');
    
    return ['package.json', 'src/App.tsx', 'src/index.tsx', 'public/index.html'];
  }
  
  private async runDevCommand(args: unknown) {
    const params = RunCommandSchema.parse(args);
    
    try {
      const { stdout, stderr } = await execAsync(params.command, {
        cwd: params.cwd || process.cwd(),
        env: { ...process.env, ...params.env },
      });
      
      return {
        success: true,
        stdout,
        stderr,
        command: params.command,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
        stdout: error.stdout,
        stderr: error.stderr,
        command: params.command,
      };
    }
  }
  
  private async generateBoilerplate(args: unknown) {
    const params = GenerateBoilerplateSchema.parse(args);
    const targetDir = params.directory;
    
    await fs.mkdir(targetDir, { recursive: true });
    
    let content = '';
    let filename = '';
    
    switch (params.type) {
      case 'component':
        content = this.generateReactComponent(params.name, params.options);
        filename = `${params.name}.tsx`;
        break;
      case 'service':
        content = this.generateService(params.name, params.options);
        filename = `${params.name.toLowerCase()}.service.ts`;
        break;
      case 'test':
        content = this.generateTest(params.name, params.options);
        filename = `${params.name.toLowerCase()}.test.ts`;
        break;
      case 'api-endpoint':
        content = this.generateAPIEndpoint(params.name, params.options);
        filename = `${params.name.toLowerCase()}.route.ts`;
        break;
      case 'model':
        content = this.generateModel(params.name, params.options);
        filename = `${params.name.toLowerCase()}.model.ts`;
        break;
    }
    
    const filePath = path.join(targetDir, filename);
    await fs.writeFile(filePath, content);
    
    return {
      success: true,
      filePath,
      type: params.type,
      name: params.name,
    };
  }
  
  private generateReactComponent(name: string, options: any = {}) {
    const { useState = false, useEffect = false, props = [] } = options;
    
    return `import React${useState ? ', { useState }' : ''}${useEffect ? ', { useEffect }' : ''} from 'react';

interface ${name}Props {
${props.map((p: any) => `  ${p.name}: ${p.type};`).join('\\n')}
}

export const ${name}: React.FC<${name}Props> = (${props.length > 0 ? 'props' : ''}) => {
${useState ? '  const [state, setState] = useState();\\n' : ''}
${useEffect ? `  useEffect(() => {
    // Effect logic here
  }, []);\\n` : ''}
  return (
    <div>
      <h1>${name} Component</h1>
      {/* Add your component content here */}
    </div>
  );
};
`;
  }
  
  private generateService(name: string, _options: any = {}) {
    return `export class ${name}Service {
  constructor() {
    // Initialize service
  }
  
  async get${name}(): Promise<any> {
    // Implement get logic
    throw new Error('Not implemented');
  }
  
  async create${name}(data: any): Promise<any> {
    // Implement create logic
    throw new Error('Not implemented');
  }
  
  async update${name}(id: string, data: any): Promise<any> {
    // Implement update logic
    throw new Error('Not implemented');
  }
  
  async delete${name}(id: string): Promise<boolean> {
    // Implement delete logic
    throw new Error('Not implemented');
  }
}
`;
  }
  
  private generateTest(name: string, _options: any = {}) {
    return `import { describe, test, expect, beforeEach } from '@jest/globals';

describe('${name}', () => {
  beforeEach(() => {
    // Setup before each test
  });
  
  test('should work correctly', () => {
    // Arrange
    const expected = true;
    
    // Act
    const result = true;
    
    // Assert
    expect(result).toBe(expected);
  });
  
  test('should handle edge cases', () => {
    // Add edge case tests
  });
});
`;
  }
  
  private generateAPIEndpoint(name: string, options: any = {}) {
    const { method = 'GET', auth = false } = options;
    
    return `import { Router, Request, Response } from 'express';
${auth ? "import { authenticate } from '../middleware/auth';" : ''}

const router = Router();

router.${method.toLowerCase()}('/${name.toLowerCase()}', ${auth ? 'authenticate, ' : ''}async (req: Request, res: Response) => {
  try {
    // Implement ${method} logic for ${name}
    
    res.json({
      success: true,
      data: {},
    });
  } catch (error) {
    console.error('Error in ${name} endpoint:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
});

export default router;
`;
  }
  
  private generateModel(name: string, options: any = {}) {
    const { fields = [] } = options;
    
    return `export interface ${name} {
  id: string;
${fields.map((f: any) => `  ${f.name}: ${f.type};`).join('\\n')}
  createdAt: Date;
  updatedAt: Date;
}

export class ${name}Model {
  constructor(private data: ${name}) {}
  
  validate(): boolean {
    // Add validation logic
    return true;
  }
  
  toJSON(): ${name} {
    return { ...this.data };
  }
}
`;
  }
  
  private async setupDevEnvironment(args: unknown) {
    const params = z.object({
      projectPath: z.string(),
      environment: z.enum(['node', 'python', 'java', 'go', 'rust']),
      installDependencies: z.boolean().optional(),
    }).parse(args);
    
    const commands: string[] = [];
    
    switch (params.environment) {
      case 'node':
        commands.push('npm init -y');
        if (params.installDependencies) {
          commands.push('npm install');
        }
        break;
      case 'python':
        commands.push('python -m venv venv');
        commands.push('echo "venv/" >> .gitignore');
        if (params.installDependencies) {
          commands.push('./venv/bin/pip install -r requirements.txt');
        }
        break;
      // Add more environments as needed
    }
    
    const results = [];
    for (const command of commands) {
      try {
        const { stdout, stderr } = await execAsync(command, {
          cwd: params.projectPath,
        });
        results.push({ command, success: true, stdout, stderr });
      } catch (error: any) {
        results.push({ 
          command, 
          success: false, 
          error: error.message,
          stdout: error.stdout,
          stderr: error.stderr,
        });
      }
    }
    
    return {
      success: results.every(r => r.success),
      environment: params.environment,
      projectPath: params.projectPath,
      results,
    };
  }
  
  private getNextSteps(template: string): string[] {
    switch (template) {
      case 'fastapi':
        return [
          'cd into your project directory',
          'Create a virtual environment: python -m venv venv',
          'Activate virtual environment: source venv/bin/activate (Linux/Mac) or venv\\\\Scripts\\\\activate (Windows)',
          'Install dependencies: pip install -r requirements.txt',
          'Run the server: uvicorn main:app --reload',
        ];
      case 'express':
        return [
          'cd into your project directory',
          'Install dependencies: npm install',
          'Run the development server: npm run dev',
        ];
      case 'react':
        return [
          'cd into your project directory',
          'Install dependencies: npm install',
          'Start the development server: npm start',
        ];
      default:
        return ['cd into your project directory'];
    }
  }
  
  // Abstract method implementations
  protected async setupResources(): Promise<void> {
    // Development Workflow server doesn't need resources
    this.logger.info('Development Workflow server: No resources to setup');
  }
  
  protected async readResource(uri: string): Promise<{ uri: string; mimeType?: string; text?: string; blob?: string }> {
    throw new Error(`Resource not found: ${uri}`);
  }
  
  protected async cleanup(): Promise<void> {
    this.logger.info('Development Workflow server cleanup completed');
  }
}

// Start the server if this file is run directly
if (require.main === module) {
  const server = new DevelopmentWorkflowServer();
  server.start().catch(console.error);
}