// A $filter evaluator for the fake F&O of the evals. The fake in test/support.mjs only understands eq clauses joined
// with and and applies just the company of any other filter, which is enough for the tests but would mislead a model:
// an or chain or a contains() would come back as every row of the company. This one evaluates and, or, not and the
// comparison operators like F&O does and answers the errors F&O gives for what it rejects, see FILTER_RULES in
// src/server.ts. Plug it in with cloud.faults.filterRows = filterRows.
import { ENUMS, PUBLIC_ENTITIES } from "../test/support.mjs";

const NAMESPACE = "Microsoft.Dynamics.DataEntities.";
const EDM = { String: "Edm.String", Real: "Edm.Decimal", Int32: "Edm.Int32", Int64: "Edm.Int64", Date: "Edm.Date", UtcDateTime: "Edm.DateTimeOffset" };
const KINDS = { eq: "Equal", ne: "NotEqual", gt: "GreaterThan", ge: "GreaterThanOrEqual", lt: "LessThan", le: "LessThanOrEqual" };

/** A filter F&O refuses, with the body of its 400. */
class Refused extends Error {
  constructor(body) {
    super(body.error.message);
    this.body = body;
  }
}

const refused = (message) => new Refused({ error: { code: "", message } });
// F&O puts this one inside innererror, like the message the tests use for contains.
const notQueryable = (message) => new Refused({ error: { code: "", message: "An error has occurred.", innererror: { message } } });

/** The rows a filter keeps, or the 400 F&O answers for it. The signature is the one of faults.filterRows. */
export function filterRows(filter, rows, collection) {
  if (!filter.trim()) return { rows };
  const entity = PUBLIC_ENTITIES[collection];
  try {
    const tree = new Parser(filter).parse();
    check(tree, entity);
    return { rows: rows.filter((row) => evaluate(tree, row, entity)) };
  } catch (error) {
    if (error instanceof Refused) return { error: [400, error.body] };
    throw error;
  }
}

/** Tokens: ( ) , 'string', date, number, a name, a name directly followed by 'value' (an enum literal) and anything else. */
const TOKEN = /\s*(?:(\()|(\))|(,)|'((?:[^']|'')*)'|(\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})?)?)(?![\w:])|(-?\d+(?:\.\d+)?)(?![\w.])|([A-Za-z_][\w.]*(?:\/[A-Za-z_]\w*)*)(?:'((?:[^']|'')*)')?|(\S))/y;

class Parser {
  constructor(text) {
    this.text = text;
    this.tokens = [];
    TOKEN.lastIndex = 0;
    while (TOKEN.lastIndex < text.length) {
      const at = TOKEN.lastIndex;
      const m = TOKEN.exec(text);
      if (!m) break;
      const [, open, close, comma, string, date, number, name, enumValue, other] = m;
      const position = at + m[0].length - m[0].trimStart().length;
      if (open) this.tokens.push({ type: "(", position });
      else if (close) this.tokens.push({ type: ")", position });
      else if (comma) this.tokens.push({ type: ",", position });
      else if (string !== undefined) this.tokens.push({ type: "literal", value: { kind: "string", value: string.replace(/''/g, "'") }, position });
      else if (date) this.tokens.push({ type: "literal", value: { kind: "date", value: date }, position });
      else if (number) this.tokens.push({ type: "literal", value: { kind: "number", value: Number(number) }, position });
      else if (name && enumValue !== undefined) this.tokens.push({ type: "literal", value: { kind: "enum", enumType: name, value: enumValue.replace(/''/g, "'") }, position });
      else if (name) this.tokens.push({ type: "name", value: name, position });
      else this.tokens.push({ type: "other", value: other, position });
    }
    this.index = 0;
  }

  peek(offset = 0) {
    return this.tokens[this.index + offset];
  }

  word(value) {
    const token = this.peek();
    return token?.type === "name" && token.value.toLowerCase() === value;
  }

  /** The OData syntax error for an unexpected token, the one F&O answers for Name in ('a','b'). */
  expected() {
    const position = this.peek()?.position ?? this.text.length;
    return refused(`Syntax error: ')' or operator expected at position ${position} in '${this.text}'.`);
  }

  parse() {
    const tree = this.or();
    if (this.peek()) throw this.expected();
    return tree;
  }

  or() {
    let left = this.and();
    while (this.word("or")) {
      this.index++;
      left = { type: "or", left, right: this.and() };
    }
    return left;
  }

  and() {
    let left = this.unary();
    while (this.word("and")) {
      this.index++;
      left = { type: "and", left, right: this.unary() };
    }
    return left;
  }

  unary() {
    if (this.word("not")) {
      this.index++;
      return { type: "not", operand: this.unary() };
    }
    if (this.peek()?.type === "(") {
      this.index++;
      const inner = this.or();
      if (this.peek()?.type !== ")") throw this.expected();
      this.index++;
      return inner;
    }
    const left = this.operand();
    const op = this.peek();
    if (op?.type !== "name" || !KINDS[op.value.toLowerCase()]) throw this.expected();
    this.index++;
    return { type: "compare", op: op.value.toLowerCase(), left, right: this.operand() };
  }

  operand() {
    const token = this.peek();
    if (!token) throw this.expected();
    if (token.type === "name" && this.peek(1)?.type === "(") throw notQueryable(`Function ${token.value} is not Queryable.`);
    this.index++;
    if (token.type === "literal") return token.value;
    if (token.type === "name") {
      const lower = token.value.toLowerCase();
      if (lower === "true" || lower === "false") return { kind: "boolean", value: lower === "true" };
      if (lower === "null") return { kind: "null" };
      if (token.value.includes("/")) throw refused("The query specified in the URI is not valid. Navigation paths in $filter are not available in this environment.");
      return { kind: "field", name: token.value };
    }
    throw this.expected();
  }
}

/** The OData type of an operand, for the incompatible types error. */
function typeOf(operand, entity) {
  if (operand.kind === "field") {
    const property = entity.Properties.find((p) => p.Name === operand.name);
    return property.DataType === "Enum" ? `${NAMESPACE}${property.TypeName}` : (EDM[property.DataType] ?? `Edm.${property.DataType}`);
  }
  if (operand.kind === "enum") return operand.enumType;
  if (operand.kind === "number") return Number.isInteger(operand.value) ? "Edm.Int32" : "Edm.Decimal";
  return { string: "Edm.String", boolean: "Edm.Boolean", date: "Edm.Date", null: "null" }[operand.kind];
}

/**
 * Refuse unknown fields, comparisons of incompatible types and range operators on strings, like F&O. An enum field takes
 * only an enum literal of its own type: a plain string such as Blocked eq 'No' is an Edm.String to F&O, so FILTER_RULES
 * tells the model to write Microsoft.Dynamics.DataEntities.CustVendorBlocked'No'. A fake that took both would pass a
 * model that fails on a real environment.
 */
function check(node, entity) {
  if (node.type === "and" || node.type === "or") {
    check(node.left, entity);
    check(node.right, entity);
    return;
  }
  if (node.type === "not") {
    check(node.operand, entity);
    return;
  }
  for (const side of [node.left, node.right]) {
    if (side.kind === "field" && !entity.Properties.some((p) => p.Name === side.name)) {
      throw refused(`Could not find a property named '${side.name}' on type '${NAMESPACE}${entity.Name}'.`);
    }
  }
  const field = [node.left, node.right].find((s) => s.kind === "field");
  const literal = [node.left, node.right].find((s) => s !== field);
  if (!field || literal.kind === "null" || literal.kind === "field") return;
  const property = entity.Properties.find((p) => p.Name === field.name);
  const fits = {
    String: ["string"], Real: ["number"], Int32: ["number"], Int64: ["number"], Date: ["date"], UtcDateTime: ["date"], Enum: ["enum"],
  }[property.DataType] ?? ["string", "number", "date"];
  const otherEnum = literal.kind === "enum" && literal.enumType.toLowerCase() !== `${NAMESPACE}${property.TypeName}`.toLowerCase();
  if (!fits.includes(literal.kind) || otherEnum) {
    throw refused(
      "A binary operator with incompatible types was detected. " +
        `Found operand types '${typeOf(node.left, entity)}' and '${typeOf(node.right, entity)}' for operator kind '${KINDS[node.op]}'.`
    );
  }
  const elements = literal.kind === "enum" ? ENUMS[property.TypeName] : undefined;
  if (elements && !elements.some((e) => e.toLowerCase() === literal.value.toLowerCase())) {
    throw refused(`The string '${literal.value}' is not a valid enumeration type constant.`);
  }
  if (["String", "Enum"].includes(property.DataType) && !["eq", "ne"].includes(node.op)) {
    throw notQueryable(`The ${node.op} operator on ${property.DataType} field ${property.Name} is not Queryable.`);
  }
}

/** F&O's string eq: case insensitive, and a * matches any run of characters. */
function like(value, pattern) {
  const escape = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^${pattern.split("*").map(escape).join(".*")}$`, "is").test(String(value ?? ""));
}

function evaluate(node, row, entity) {
  if (node.type === "and") return evaluate(node.left, row, entity) && evaluate(node.right, row, entity);
  if (node.type === "or") return evaluate(node.left, row, entity) || evaluate(node.right, row, entity);
  if (node.type === "not") return !evaluate(node.operand, row, entity);
  const value = (side) => (side.kind === "field" ? row[side.name] : side.kind === "null" ? null : side.value);
  // Keep the field on the left, so 'x' eq Name reads like Name eq 'x'.
  const swapped = node.left.kind !== "field" && node.right.kind === "field";
  const [left, right] = swapped ? [node.right, node.left] : [node.left, node.right];
  const op = swapped ? { gt: "lt", ge: "le", lt: "gt", le: "ge" }[node.op] ?? node.op : node.op;
  const [a, b] = [value(left), value(right)];
  if (right.kind === "null") return op === "eq" ? a === null || a === undefined || a === "" : !(a === null || a === undefined || a === "");
  if (right.kind === "string" && (op === "eq" || op === "ne")) return like(a, b) === (op === "eq");
  if (right.kind === "enum") return (String(a).toLowerCase() === String(b).toLowerCase()) === (op === "eq");
  let [x, y] = [a, b];
  if (right.kind === "date") {
    const property = entity.Properties.find((p) => p.Name === left.name);
    // Date fields carry a time of 12:00 that means nothing, so they compare by the date part.
    [x, y] = property?.DataType === "Date" ? [String(a).slice(0, 10), String(b).slice(0, 10)] : [Date.parse(a), Date.parse(b.length === 10 ? `${b}T00:00:00Z` : b)];
  } else if (right.kind === "number") {
    [x, y] = [Number(a), Number(b)];
  }
  return { eq: x === y, ne: x !== y, gt: x > y, ge: x >= y, lt: x < y, le: x <= y }[op];
}
