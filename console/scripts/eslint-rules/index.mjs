// @ts-check
/** @typedef {import('eslint').Rule.RuleModule} RuleModule */
/** @type {RuleModule} */
const foundation = {
  meta: {
    type: 'problem',
    schema: [],
    messages: {
      forbidden: 'Foundation forbids this sink or binding.',
      untranslated: 'Use a literal translation key or a reviewed finite key list.',
    },
  },
  create(context) {
    const banned = new Set([
      'innerHTML',
      'outerHTML',
      'insertAdjacentHTML',
      'write',
      'writeln',
      'parseFromString',
      'createContextualFragment',
      'eval',
      'Function',
      'insertRule',
      'replaceSync',
      'createPolicy',
      'compile',
      'unsafeToTrustedHTML',
    ])
    /** @param {import('./nodes.ts').Node} node */
    function report(node) {
      context.report({ node, messageId: 'forbidden' })
    }
    /** @param {import('./nodes.ts').Node} node */
    function finiteOption(node) {
      for (let parent = node.parent; parent; parent = parent.parent) {
        if (
          parent.type === 'VElement' &&
          parent.startTag?.attributes.some((attribute) => {
            const expression = attribute.value?.expression
            return (
              attribute.directive &&
              attribute.key.name.name === 'for' &&
              expression?.type === 'VForExpression' &&
              expression.left?.some(
                (variable) => variable.type === 'Identifier' && variable.name === 'option',
              ) &&
              expression.right?.type === 'Identifier' &&
              ['localeOptions', 'themeOptions', 'densityOptions'].includes(
                expression.right.name ?? '',
              )
            )
          })
        )
          return true
      }
      return false
    }
    const scriptVisitor = {
      /** @param {import('./nodes.ts').Node} node */
      ImportDeclaration(node) {
        if (node.specifiers?.some((specifier) => banned.has(specifier.imported?.name ?? '')))
          report(node)
      },
      /** @param {import('./nodes.ts').Node} node */
      AssignmentExpression(node) {
        if (
          node.left?.type === 'MemberExpression' &&
          ['title', 'textContent', 'innerText'].includes(node.left.property?.name ?? '') &&
          node.right?.type === 'Literal' &&
          typeof node.right.value === 'string'
        )
          context.report({ node, messageId: 'untranslated' })
      },
      /** @param {import('./nodes.ts').Node} node */
      MemberExpression(node) {
        const name =
          !node.computed && node.property?.type === 'Identifier'
            ? node.property.name
            : node.property?.type === 'Literal'
              ? node.property.value
              : undefined
        if (typeof name === 'string' && (banned.has(name) || name === 'replace')) report(node)
      },
      /** @param {import('./nodes.ts').Node} node */
      CallExpression(node) {
        const name =
          node.callee?.type === 'Identifier'
            ? node.callee.name
            : node.callee?.type === 'MemberExpression' &&
                node.callee.property?.type === 'Identifier'
              ? node.callee.property.name
              : undefined
        const first = node.arguments?.[0]
        if (name && banned.has(name)) report(node)
        if (
          (name === 'setTimeout' || name === 'setInterval') &&
          first?.type !== 'ArrowFunctionExpression' &&
          first?.type !== 'FunctionExpression' &&
          first?.type !== 'Identifier'
        )
          report(node)
        if (
          name === 'createElement' &&
          (first?.type !== 'Literal' || first.value === 'script' || first.value === 'style')
        )
          report(node)
        if (
          (name === 't' || name === 'translateCount') &&
          first?.type !== 'Literal' &&
          !(
            first?.type === 'Identifier' &&
            ((first.name === 'key' && context.filename.endsWith('src/app/i18n.ts')) ||
              (first.name === 'titleKey' && context.filename.endsWith('src/app/App.vue')))
          ) &&
          !(
            first?.type === 'MemberExpression' &&
            first.object?.type === 'Identifier' &&
            first.object.name === 'option' &&
            first.property?.type === 'Identifier' &&
            first.property.name === 'key' &&
            finiteOption(node)
          )
        )
          context.report({ node, messageId: 'untranslated' })
      },
      /** @param {import('./nodes.ts').Node} node */
      NewExpression(node) {
        scriptVisitor.CallExpression(node)
      },
    }
    const services = context.sourceCode.parserServices
    if (!services.defineTemplateBodyVisitor) return scriptVisitor
    // Vue parser nodes extend ESTree with template nodes.
    return services.defineTemplateBodyVisitor(
      {
        /** @param {{type: string, value: string}} node */
        VText(node) {
          if (
            node.value.trim() &&
            !['Ricevanta', 'English', 'Tiếng Việt'].includes(node.value.trim())
          )
            context.report({ node, messageId: 'untranslated' })
        },
        /** @param {{type: string, directive: boolean, key: {name: string | {name: string}, argument?: {type: string, name?: string, rawName?: string} | null, modifiers?: {name: string, rawName?: string}[]}, value?: {value?: string, expression?: import('./nodes.ts').Node | null} | null}} node */
        VAttribute(node) {
          if (node.directive) {
            const name = typeof node.key.name === 'object' ? node.key.name.name : node.key.name
            let binding = node.key.argument?.rawName ?? node.key.argument?.name ?? ''
            // Vue 3.5.43 camelizes before adding prop/attr dispatch prefixes.
            // Those prefixes select patching mode; the sink name stays the argument.
            if (
              node.key.modifiers?.some(
                (modifier) => (modifier.rawName ?? modifier.name) === 'camel',
              )
            )
              binding = binding.replace(/-\w/g, (part) => part.slice(1).toUpperCase())
            if (
              name === 'html' ||
              (name === 'bind' &&
                (!node.key.argument ||
                  node.key.argument.type !== 'VIdentifier' ||
                  ['style', 'innerhtml', 'outerhtml', 'inner-html', 'outer-html'].includes(
                    binding.toLowerCase(),
                  )))
            )
              context.report({ node, messageId: 'forbidden' })
            if (
              name === 'bind' &&
              ['title', 'alt', 'placeholder', 'aria-label'].includes(node.key.argument?.name ?? '')
            ) {
              const expression = node.value?.expression
              if (
                !(
                  expression?.type === 'CallExpression' &&
                  expression.callee?.type === 'Identifier' &&
                  ['t', 'translateCount'].includes(expression.callee.name ?? '')
                ) &&
                !(
                  expression?.type === 'Literal' &&
                  ['', 'Ricevanta', 'English', 'Tiếng Việt'].includes(String(expression.value))
                )
              )
                context.report({ node, messageId: 'untranslated' })
            }
          } else if (
            typeof node.key.name === 'string' &&
            ['title', 'alt', 'placeholder', 'aria-label'].includes(node.key.name) &&
            node.value?.value &&
            !['Ricevanta', 'English', 'Tiếng Việt'].includes(node.value.value)
          )
            context.report({ node, messageId: 'untranslated' })
        },
        /** @param {{type: string, expression?: import('./nodes.ts').Node | null, parent?: {type: string}}} node */
        VExpressionContainer(node) {
          if (
            node.parent?.type === 'VElement' &&
            node.expression?.type === 'Literal' &&
            typeof node.expression.value === 'string' &&
            node.expression.value.trim() &&
            !['Ricevanta', 'English', 'Tiếng Việt'].includes(node.expression.value)
          )
            context.report({ node, messageId: 'untranslated' })
        },
        ...scriptVisitor,
      },
      scriptVisitor,
    )
  },
}
export default { rules: { foundation } }
