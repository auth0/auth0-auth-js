import type {
  ToolDefinition,
  LocalToolDefinition,
  McpToolDefinition,
  ApiUpstreamOptions,
} from './types.js';

export interface RegisteredTool {
  definition: ToolDefinition | LocalToolDefinition;
  upstream?: ApiUpstreamOptions;
  isLocal: boolean;
}

export class ToolRegistry {
  readonly #tools = new Map<string, RegisteredTool>();

  registerRemote(definition: ToolDefinition, upstream: ApiUpstreamOptions): void {
    this.#validateName(definition.name);
    this.#tools.set(definition.name, { definition, upstream, isLocal: false });
  }

  registerLocal(definition: LocalToolDefinition): void {
    this.#validateName(definition.name);
    this.#tools.set(definition.name, { definition, upstream: undefined, isLocal: true });
  }

  get(name: string): RegisteredTool | undefined {
    return this.#tools.get(name);
  }

  list(): McpToolDefinition[] {
    return Array.from(this.#tools.values()).map((entry) => ({
      name: entry.definition.name,
      description: entry.definition.description,
      inputSchema: entry.definition.schema,
    }));
  }

  listForScopes(scopes: string[]): McpToolDefinition[] {
    const scopeSet = new Set(scopes);
    return Array.from(this.#tools.values())
      .filter((entry) => {
        const required = entry.definition.scopes;
        if (!required || required.length === 0) return true;
        return required.every((s) => scopeSet.has(s));
      })
      .map((entry) => ({
        name: entry.definition.name,
        description: entry.definition.description,
        inputSchema: entry.definition.schema,
      }));
  }

  allScopes(): string[] {
    const scopes = new Set<string>();
    for (const entry of this.#tools.values()) {
      if (entry.definition.scopes) {
        for (const s of entry.definition.scopes) {
          scopes.add(s);
        }
      }
    }
    return Array.from(scopes);
  }

  #validateName(name: string): void {
    if (!name || typeof name !== 'string') {
      throw new Error('Tool name must be a non-empty string');
    }
    if (this.#tools.has(name)) {
      throw new Error(`Tool "${name}" is already registered`);
    }
  }
}
