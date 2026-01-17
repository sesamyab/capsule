"use client";

interface CodeBlockProps {
  children: string;
  language?: "javascript" | "typescript" | "bash" | "json" | "php" | "python";
}

export function CodeBlock({ children, language = "typescript" }: CodeBlockProps) {
  const highlighted = highlightCode(children.trim(), language);
  
  return (
    <pre className="code-block">
      <code dangerouslySetInnerHTML={{ __html: highlighted }} />
    </pre>
  );
}

function highlightCode(code: string, language: string): string {
  // Escape HTML first
  let html = code
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  // Apply syntax highlighting based on language
  if (language === "bash") {
    html = highlightBash(html);
  } else if (language === "json") {
    html = highlightJson(html);
  } else if (language === "php") {
    html = highlightPhp(html);
  } else if (language === "python") {
    html = highlightPython(html);
  } else {
    html = highlightJavaScript(html);
  }

  return html;
}

function highlightJavaScript(code: string): string {
  // Use placeholder approach to prevent re-processing highlighted content
  const placeholders: string[] = [];
  
  // Helper to store content and return placeholder
  const placeholder = (content: string, className: string) => {
    const index = placeholders.length;
    placeholders.push(`<span class="hljs-${className}">${content}</span>`);
    return `__PLACEHOLDER_${index}__`;
  };
  
  // Comments first (single line and multi-line) - store as placeholders
  code = code.replace(/(\/\/.*$)/gm, (match) => placeholder(match, 'comment'));
  code = code.replace(/(\/\*[\s\S]*?\*\/)/g, (match) => placeholder(match, 'comment'));

  // Strings (double and single quotes, template literals) - store as placeholders
  code = code.replace(/(&quot;[^&]*&quot;)/g, (match) => placeholder(match, 'string'));
  code = code.replace(/('[^']*')/g, (match) => placeholder(match, 'string'));
  code = code.replace(/(`[^`]*`)/g, (match) => placeholder(match, 'string'));

  // Keywords
  const keywords = [
    "import", "export", "from", "const", "let", "var", "function", "async", 
    "await", "return", "if", "else", "for", "while", "class", "extends",
    "new", "this", "typeof", "instanceof", "throw", "try", "catch", "finally",
    "default", "switch", "case", "break", "continue", "interface", "type"
  ];
  const keywordRegex = new RegExp(`\\b(${keywords.join("|")})\\b`, "g");
  code = code.replace(keywordRegex, '<span class="hljs-keyword">$1</span>');

  // Built-in objects and types
  const builtins = [
    "Buffer", "Promise", "Array", "Object", "String", "Number", "Boolean",
    "Map", "Set", "Date", "JSON", "Math", "console", "crypto", "window",
    "document", "Error", "Response", "Request", "NextRequest", "NextResponse"
  ];
  const builtinRegex = new RegExp(`\\b(${builtins.join("|")})\\b`, "g");
  code = code.replace(builtinRegex, '<span class="hljs-built_in">$1</span>');

  // Function calls (word followed by parenthesis)
  code = code.replace(/\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g, '<span class="hljs-function">$1</span>(');

  // Numbers
  code = code.replace(/\b(\d+)\b/g, '<span class="hljs-number">$1</span>');

  // Properties after dot
  code = code.replace(/\.([a-zA-Z_][a-zA-Z0-9_]*)/g, '.<span class="hljs-property">$1</span>');

  // Restore placeholders
  placeholders.forEach((content, index) => {
    code = code.replace(`__PLACEHOLDER_${index}__`, content);
  });

  return code;
}

function highlightBash(code: string): string {
  // Use placeholder approach to prevent re-processing highlighted content
  const placeholders: string[] = [];
  
  const placeholder = (content: string, className: string) => {
    const index = placeholders.length;
    placeholders.push(`<span class="hljs-${className}">${content}</span>`);
    return `__PLACEHOLDER_${index}__`;
  };
  
  // Comments
  code = code.replace(/(#.*$)/gm, (match) => placeholder(match, 'comment'));

  // Strings
  code = code.replace(/(&quot;[^&]*&quot;)/g, (match) => placeholder(match, 'string'));
  code = code.replace(/('[^']*')/g, (match) => placeholder(match, 'string'));

  // Commands at start of line or after pipe/semicolon
  const commands = ["npm", "npx", "yarn", "pip", "python", "node", "php", "cd", "mkdir", "git", "curl", "install"];
  const cmdRegex = new RegExp(`\\b(${commands.join("|")})\\b`, "g");
  code = code.replace(cmdRegex, '<span class="hljs-keyword">$1</span>');

  // Restore placeholders
  placeholders.forEach((content, index) => {
    code = code.replace(`__PLACEHOLDER_${index}__`, content);
  });

  return code;
}

function highlightJson(code: string): string {
  // Property names
  code = code.replace(/(&quot;[^&]+&quot;)\s*:/g, '<span class="hljs-property">$1</span>:');

  // String values
  code = code.replace(/:\s*(&quot;[^&]*&quot;)/g, ': <span class="hljs-string">$1</span>');

  // Numbers
  code = code.replace(/:\s*(\d+)/g, ': <span class="hljs-number">$1</span>');

  // Booleans and null
  code = code.replace(/:\s*(true|false|null)/g, ': <span class="hljs-keyword">$1</span>');

  return code;
}

function highlightPhp(code: string): string {
  // Use placeholder approach to prevent re-processing highlighted content
  const placeholders: string[] = [];
  
  const placeholder = (content: string, className: string) => {
    const index = placeholders.length;
    placeholders.push(`<span class="hljs-${className}">${content}</span>`);
    return `__PLACEHOLDER_${index}__`;
  };
  
  // Comments
  code = code.replace(/(\/\/.*$)/gm, (match) => placeholder(match, 'comment'));
  code = code.replace(/(#.*$)/gm, (match) => placeholder(match, 'comment'));
  code = code.replace(/(\/\*[\s\S]*?\*\/)/g, (match) => placeholder(match, 'comment'));

  // Strings
  code = code.replace(/(&quot;[^&]*&quot;)/g, (match) => placeholder(match, 'string'));
  code = code.replace(/('[^']*')/g, (match) => placeholder(match, 'string'));

  // PHP keywords
  const keywords = [
    "function", "return", "if", "else", "for", "foreach", "while", "class",
    "public", "private", "protected", "static", "new", "use", "namespace",
    "throw", "try", "catch", "array", "echo", "require", "include"
  ];
  const keywordRegex = new RegExp(`\\b(${keywords.join("|")})\\b`, "g");
  code = code.replace(keywordRegex, '<span class="hljs-keyword">$1</span>');

  // Variables
  code = code.replace(/(\$[a-zA-Z_][a-zA-Z0-9_]*)/g, '<span class="hljs-variable">$1</span>');

  // Numbers
  code = code.replace(/\b(\d+)\b/g, '<span class="hljs-number">$1</span>');

  // Restore placeholders
  placeholders.forEach((content, index) => {
    code = code.replace(`__PLACEHOLDER_${index}__`, content);
  });

  return code;
}

function highlightPython(code: string): string {
  // Use placeholder approach to prevent re-processing highlighted content
  const placeholders: string[] = [];
  
  const placeholder = (content: string, className: string) => {
    const index = placeholders.length;
    placeholders.push(`<span class="hljs-${className}">${content}</span>`);
    return `__PLACEHOLDER_${index}__`;
  };
  
  // Comments
  code = code.replace(/(#.*$)/gm, (match) => placeholder(match, 'comment'));

  // Strings (triple quotes, double, single)
  code = code.replace(/(&quot;&quot;&quot;[\s\S]*?&quot;&quot;&quot;|'''[\s\S]*?''')/g, (match) => placeholder(match, 'string'));
  code = code.replace(/(&quot;[^&]*&quot;)/g, (match) => placeholder(match, 'string'));
  code = code.replace(/('[^']*')/g, (match) => placeholder(match, 'string'));

  // Keywords
  const keywords = [
    "import", "from", "def", "class", "return", "if", "elif", "else",
    "for", "while", "try", "except", "finally", "with", "as", "raise",
    "pass", "break", "continue", "and", "or", "not", "in", "is", "None",
    "True", "False", "lambda", "yield", "async", "await"
  ];
  const keywordRegex = new RegExp(`\\b(${keywords.join("|")})\\b`, "g");
  code = code.replace(keywordRegex, '<span class="hljs-keyword">$1</span>');

  // Function calls
  code = code.replace(/\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g, '<span class="hljs-function">$1</span>(');

  // Numbers
  code = code.replace(/\b(\d+)\b/g, '<span class="hljs-number">$1</span>');

  // Restore placeholders
  placeholders.forEach((content, index) => {
    code = code.replace(`__PLACEHOLDER_${index}__`, content);
  });

  return code;
}
