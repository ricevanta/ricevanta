//
// Copyright (c) 2011-2019 Canonical Ltd
// Copyright (c) 2006-2010 Kirill Simonov
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is furnished to do
// so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package yamltokens

import (
	"io"
	"unsafe"
)

func yaml_insert_token(parser *yaml_parser_t, pos int, token *yaml_token_t) {
	if parser.guardErr != nil {
		return
	}
	if parser.emitted == maxTokens || len(token.value)+len(token.prefix)+len(token.suffix) > maxBytes-parser.tokenBytes {
		parser.fail(ErrLimit)
		return
	}
	if parser.ends != 0 && token.typ != yaml_STREAM_END_TOKEN {
		parser.fail(ErrSyntax)
		return
	}
	if token.typ == yaml_DOCUMENT_START_TOKEN {
		parser.starts++
		if parser.starts > 1 {
			parser.fail(ErrSyntax)
			return
		}
	}
	if token.typ == yaml_DOCUMENT_END_TOKEN {
		parser.ends++
	}
	parser.emitted++
	parser.tokenBytes += len(token.value) + len(token.prefix) + len(token.suffix)

	//fmt.Println("yaml_insert_token", "pos:", pos, "typ:", token.typ, "head:", parser.tokens_head, "len:", len(parser.tokens))

	// Check if we can move the queue at the beginning of the buffer.
	if parser.tokens_head > 0 && len(parser.tokens) == cap(parser.tokens) {
		if parser.tokens_head != len(parser.tokens) {
			copy(parser.tokens, parser.tokens[parser.tokens_head:])
		}
		parser.tokens = parser.tokens[:len(parser.tokens)-parser.tokens_head]
		parser.tokens_head = 0
	}
	// Preserve pinned append capacities: a parser token pointer may survive
	// lookahead that compacts this queue. Charge a conservative growth bound.
	if len(parser.tokens) == cap(parser.tokens) {
		if !reserveParser(parser, "tokens", uint64(max(1, cap(parser.tokens)*2))*uint64(unsafe.Sizeof(*token)), 1) {
			return
		}
	}
	parser.tokens = append(parser.tokens, *token)
	if pos < 0 {
		return
	}
	copy(parser.tokens[parser.tokens_head+pos+1:], parser.tokens[parser.tokens_head+pos:])
	parser.tokens[parser.tokens_head+pos] = *token
}

// Create a new parser object.
func yaml_parser_initialize(parser *yaml_parser_t) bool {
	b := parser.budget
	if b == nil {
		b = newBudget()
	}
	*parser = yaml_parser_t{budget: b}
	if !reserveParser(parser, "reader", uint64(input_raw_buffer_size+input_buffer_size), 2) {
		return false
	}
	parser.raw_buffer = make([]byte, 0, input_raw_buffer_size)
	parser.buffer = make([]byte, 0, input_buffer_size)
	return true
}

// Destroy a parser object.
func yaml_parser_delete(parser *yaml_parser_t) {
	*parser = yaml_parser_t{}
}

// String read handler.
func yaml_string_read_handler(parser *yaml_parser_t, buffer []byte) (n int, err error) {
	if parser.input_pos == len(parser.input) {
		return 0, io.EOF
	}
	n = copy(buffer, parser.input[parser.input_pos:])
	parser.input_pos += n
	return n, nil
}

// Reader read handler.
func yaml_reader_read_handler(parser *yaml_parser_t, buffer []byte) (n int, err error) {
	return parser.input_reader.Read(buffer)
}

// Set a string input.
func yaml_parser_set_input_string(parser *yaml_parser_t, input []byte) {
	if parser.read_handler != nil {
		panic("must set the input source only once")
	}
	parser.read_handler = yaml_string_read_handler
	parser.input = input
	parser.input_pos = 0
}

// Set a file input.
func yaml_parser_set_input_reader(parser *yaml_parser_t, r io.Reader) {
	if parser.read_handler != nil {
		panic("must set the input source only once")
	}
	parser.read_handler = yaml_reader_read_handler
	parser.input_reader = r
}

// Set the source encoding.
func yaml_parser_set_encoding(parser *yaml_parser_t, encoding yaml_encoding_t) {
	if parser.encoding != yaml_ANY_ENCODING {
		panic("must set the encoding only once")
	}
	parser.encoding = encoding
}
