package egress

import (
	"strings"
)

// subst stands in for text the shell computes at run time ($(...), `...`,
// $VAR, <(...)). A URL or host containing it is dynamic: whatever ends up
// there was produced by a command, which is exactly how data gets smuggled
// out in a request.
const subst = "\x00"

// simpleCmd is one command in a pipeline or list, after quote removal.
type simpleCmd struct {
	words   []string
	heredoc string // body of a here-document fed to this command
	piped   bool   // stdin comes from a preceding "|"
	pipeTo  bool   // stdout goes to a following "|"
}

type lexed struct {
	cmds   []simpleCmd
	nested []string // bodies of $(...), `...`, <(...), >(...)
	ansiC  bool     // used $'...' with escapes, a common obfuscation
}

// lex splits a shell command line into simple commands. It is not a full
// POSIX parser; it understands enough (quotes, escapes, operators,
// substitutions, here-documents, comments) to find which programs run with
// which arguments. Anything it cannot see into is marked dynamic rather than
// guessed.
func lex(src string) lexed {
	var out lexed
	var cur simpleCmd
	var word strings.Builder
	inWord := false
	type pendingDoc struct {
		delim string
		strip bool
		cmd   int // index into out.cmds once the command is flushed; -1 = cur
	}
	var docs []pendingDoc
	redirectNext := false

	flushWord := func() {
		if !inWord {
			return
		}
		w := word.String()
		word.Reset()
		inWord = false
		if redirectNext {
			redirectNext = false
			return // redirect target: a file, not an argument
		}
		cur.words = append(cur.words, w)
	}
	flushCmd := func(pipeNext bool) {
		flushWord()
		if len(cur.words) > 0 || cur.heredoc != "" {
			cur.pipeTo = pipeNext
			out.cmds = append(out.cmds, cur)
			for i := range docs {
				if docs[i].cmd == -1 {
					docs[i].cmd = len(out.cmds) - 1
				}
			}
		}
		cur = simpleCmd{piped: pipeNext}
	}
	readHeredocs := func(i int) int {
		// i points just past a newline; consume each pending body in order.
		for _, d := range docs {
			var body strings.Builder
			for i < len(src) {
				end := strings.IndexByte(src[i:], '\n')
				var line string
				if end < 0 {
					line, i = src[i:], len(src)
				} else {
					line, i = src[i:i+end], i+end+1
				}
				cmp := line
				if d.strip {
					cmp = strings.TrimLeft(line, "\t")
				}
				if cmp == d.delim {
					break
				}
				body.WriteString(line)
				body.WriteByte('\n')
			}
			if d.cmd >= 0 && d.cmd < len(out.cmds) {
				out.cmds[d.cmd].heredoc += body.String()
			} else {
				cur.heredoc += body.String()
			}
		}
		docs = nil
		return i
	}

	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '\\' && i+1 < len(src):
			if src[i+1] == '\n' {
				i += 2 // line continuation
				continue
			}
			word.WriteByte(src[i+1])
			inWord = true
			i += 2
		case c == '\'':
			j := strings.IndexByte(src[i+1:], '\'')
			if j < 0 {
				word.WriteString(src[i+1:])
				i = len(src)
			} else {
				word.WriteString(src[i+1 : i+1+j])
				i += j + 2
			}
			inWord = true
		case c == '"':
			i++
			for i < len(src) && src[i] != '"' {
				switch {
				case src[i] == '\\' && i+1 < len(src) && strings.IndexByte("\"\\$`\n", src[i+1]) >= 0:
					word.WriteByte(src[i+1])
					i += 2
				case src[i] == '$' && i+1 < len(src) && src[i+1] == '(':
					body, n := balanced(src[i+1:])
					out.nested = append(out.nested, body)
					word.WriteString(subst)
					i += 1 + n
				case src[i] == '`':
					j := strings.IndexByte(src[i+1:], '`')
					if j < 0 {
						j = len(src) - i - 1
					}
					out.nested = append(out.nested, src[i+1:i+1+j])
					word.WriteString(subst)
					i += j + 2
				case src[i] == '$' && i+1 < len(src) && isVarStart(src[i+1]):
					word.WriteString(subst)
					i = skipVar(src, i+1)
				default:
					word.WriteByte(src[i])
					i++
				}
			}
			i++ // closing quote
			inWord = true
		case c == '$' && i+1 < len(src) && src[i+1] == '\'':
			j := i + 2
			for j < len(src) && src[j] != '\'' {
				if src[j] == '\\' {
					if j+1 < len(src) && strings.IndexByte("xu0123456789U", src[j+1]) >= 0 {
						out.ansiC = true
					}
					j++
				}
				j++
			}
			word.WriteString(subst)
			inWord = true
			i = j + 1
		case c == '$' && i+1 < len(src) && src[i+1] == '(':
			body, n := balanced(src[i+1:])
			out.nested = append(out.nested, body)
			word.WriteString(subst)
			inWord = true
			i += 1 + n
		case (c == '<' || c == '>') && i+1 < len(src) && src[i+1] == '(' && !inWord:
			body, n := balanced(src[i+1:])
			out.nested = append(out.nested, body)
			word.WriteString(subst)
			inWord = true
			i += 1 + n
		case c == '`':
			j := strings.IndexByte(src[i+1:], '`')
			if j < 0 {
				j = len(src) - i - 1
			}
			out.nested = append(out.nested, src[i+1:i+1+j])
			word.WriteString(subst)
			inWord = true
			i += j + 2
		case c == '$' && i+1 < len(src) && isVarStart(src[i+1]):
			word.WriteString(subst)
			inWord = true
			i = skipVar(src, i+1)
		case c == '#' && !inWord:
			j := strings.IndexByte(src[i:], '\n')
			if j < 0 {
				i = len(src)
			} else {
				i += j
			}
		case c == '\n':
			flushCmd(false)
			i = readHeredocs(i + 1)
		case c == ';' || c == '(' || c == ')':
			flushCmd(false)
			i++
		case c == '&':
			if i+1 < len(src) && src[i+1] == '>' { // &> file
				flushWord()
				redirectNext = true
				i += 2
				if i < len(src) && src[i] == '>' {
					i++
				}
				continue
			}
			flushCmd(false)
			i++
			if i < len(src) && src[i] == '&' {
				i++
			}
		case c == '|':
			if i+1 < len(src) && src[i+1] == '|' {
				flushCmd(false)
				i += 2
			} else {
				flushCmd(true)
				i++
				if i < len(src) && src[i] == '&' {
					i++
				}
			}
		case c == '<' && strings.HasPrefix(src[i:], "<<<"):
			flushWord()
			i += 3 // here-string: the next word is data, keep it as an argument
		case c == '<' && strings.HasPrefix(src[i:], "<<"):
			flushWord()
			i += 2
			strip := false
			if i < len(src) && src[i] == '-' {
				strip = true
				i++
			}
			for i < len(src) && (src[i] == ' ' || src[i] == '\t') {
				i++
			}
			j := i
			for j < len(src) && !isSpace(src[j]) && strings.IndexByte(";|&<>()", src[j]) < 0 {
				j++
			}
			delim := strings.Trim(src[i:j], `'"\`)
			docs = append(docs, pendingDoc{delim: delim, strip: strip, cmd: -1})
			i = j
		case c == '<' || c == '>':
			// Redirection. A leading fd number was read as a word; drop it.
			if inWord && isDigits(word.String()) {
				word.Reset()
				inWord = false
			} else {
				flushWord()
			}
			i++
			for i < len(src) && (src[i] == '>' || src[i] == '&' || src[i] == '|') {
				i++
			}
			// ">&2" style duplications have no file target.
			if i < len(src) && src[i] >= '0' && src[i] <= '9' && i > 0 && src[i-1] == '&' {
				for i < len(src) && src[i] >= '0' && src[i] <= '9' {
					i++
				}
				continue
			}
			redirectNext = true
		case isSpace(c):
			flushWord()
			i++
		default:
			word.WriteByte(c)
			inWord = true
			i++
		}
	}
	flushCmd(false)
	return out
}

// balanced returns the body of a parenthesised group starting at s[0]=='(',
// and how many bytes it spans including both parentheses.
func balanced(s string) (string, int) {
	depth := 0
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && !inS:
			i++
		case c == '\'' && !inD:
			inS = !inS
		case c == '"' && !inS:
			inD = !inD
		case inS || inD:
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return s[1:i], i + 1
			}
		}
	}
	if len(s) > 0 {
		return s[1:], len(s)
	}
	return "", 0
}

func isVarStart(c byte) bool {
	return c == '{' || c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || strings.IndexByte("@*#?$!-", c) >= 0
}

func skipVar(s string, i int) int {
	if i < len(s) && s[i] == '{' {
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			return len(s)
		}
		return i + j + 1
	}
	if i < len(s) && strings.IndexByte("@*#?$!-0123456789", s[i]) >= 0 {
		return i + 1
	}
	for i < len(s) && (s[i] == '_' || (s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	return i
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' }

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
