export interface Node {
  type: string
  name?: string
  value?: unknown
  computed?: boolean
  object?: Node
  property?: Node
  callee?: Node
  arguments?: Node[]
  left?: Node
  right?: Node
  specifiers?: Node[]
  imported?: Node
  parent?: Node
  startTag?: {
    attributes: {
      directive: boolean
      key: { name: { name: string } }
      value?: { expression?: { type: string; left?: Node[]; right?: Node } }
    }[]
  }
}
