import type {
  OpenApiSpec,
  OpenApiToolsOptions,
  OpenApiOperation,
  OpenApiParameter,
  ToolDefinition,
  HttpMethod,
  JsonSchema,
} from './types.js';

const SUPPORTED_METHODS: HttpMethod[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

export function toolsFromOpenApiSpec(
  spec: OpenApiSpec,
  options?: OpenApiToolsOptions
): ToolDefinition[] {
  const tools: ToolDefinition[] = [];
  const paths = spec.paths ?? {};

  for (const [path, pathItem] of Object.entries(paths)) {
    const pathLevelParams = pathItem.parameters ?? [];

    for (const method of SUPPORTED_METHODS) {
      const operation = pathItem[method.toLowerCase() as keyof typeof pathItem] as OpenApiOperation | undefined;
      if (!operation) continue;

      const operationId = operation.operationId;
      if (!operationId) continue;

      if (options?.include && !options.include.includes(operationId)) continue;
      if (options?.exclude && options.exclude.includes(operationId)) continue;

      const description =
        options?.descriptionOverrides?.[operationId] ??
        operation.summary ??
        operation.description ??
        operationId;

      const allParams = [...pathLevelParams, ...(operation.parameters ?? [])];
      const schema = buildSchema(allParams, operation.requestBody?.content, spec);
      const scopes = options?.scopeOverrides?.[operationId] ?? extractScopes(operation);

      tools.push({
        name: operationId,
        description,
        endpoint: { method, path },
        schema,
        ...(scopes.length > 0 && { scopes }),
      });
    }
  }

  return tools;
}

function buildSchema(
  params: OpenApiParameter[],
  requestBodyContent: Record<string, { schema?: JsonSchema }> | undefined,
  spec: OpenApiSpec
): JsonSchema {
  const properties: Record<string, JsonSchema> = {};
  const required: string[] = [];

  for (const param of params) {
    if (param.in === 'path' || param.in === 'query') {
      const resolved = param.schema ? resolveRef(param.schema, spec) : { type: 'string' };
      properties[param.name] = {
        ...resolved,
        ...(param.description && { description: param.description }),
      };
      if (param.required) {
        required.push(param.name);
      }
    }
  }

  if (requestBodyContent) {
    const jsonContent = requestBodyContent['application/json'];
    if (jsonContent?.schema) {
      const bodySchema = resolveRef(jsonContent.schema, spec);
      if (bodySchema.properties) {
        for (const [name, prop] of Object.entries(bodySchema.properties)) {
          properties[name] = resolveRef(prop, spec);
        }
        if (bodySchema.required) {
          required.push(...bodySchema.required);
        }
      }
    }
  }

  return {
    type: 'object',
    properties,
    ...(required.length > 0 && { required }),
  };
}

function resolveRef(schema: JsonSchema, spec: OpenApiSpec): JsonSchema {
  if (!schema.$ref) return schema;

  const refPath = schema.$ref.replace('#/', '').split('/');
  let current: unknown = spec;

  for (const segment of refPath) {
    if (current && typeof current === 'object') {
      current = (current as Record<string, unknown>)[segment];
    } else {
      return schema;
    }
  }

  if (current && typeof current === 'object') {
    return current as JsonSchema;
  }

  return schema;
}

function extractScopes(operation: OpenApiOperation): string[] {
  if (!operation.security) return [];

  const scopes = new Set<string>();
  for (const requirement of operation.security) {
    for (const scopeList of Object.values(requirement)) {
      for (const scope of scopeList) {
        scopes.add(scope);
      }
    }
  }
  return Array.from(scopes);
}
