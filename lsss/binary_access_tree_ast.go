package lsss

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GnarkPairingProject/hash"
)

// TokenType 定义 token 类型
type TokenType int

const (
	TokenEOF TokenType = iota
	TokenAttribute
	TokenAnd
	TokenOr
	TokenLeftParen
	TokenRightParen
)

// Token 表示一个词法单元
type Token struct {
	Type  TokenType
	Value string
}

// Lexer 词法分析器
type Lexer struct {
	input string
	pos   int
	ch    rune
}

// NewLexer 创建新的词法分析器
func NewLexer(input string) *Lexer {
	l := &Lexer{input: input}
	l.readChar()
	return l
}

func (l *Lexer) readChar() {
	if l.pos >= len(l.input) {
		l.ch = 0
	} else {
		l.ch = rune(l.input[l.pos])
	}
	l.pos++
}

func (l *Lexer) skipWhitespace() {
	for unicode.IsSpace(l.ch) {
		l.readChar()
	}
}

func (l *Lexer) readIdentifier() string {
	start := l.pos - 1
	for unicode.IsLetter(l.ch) || unicode.IsDigit(l.ch) || l.ch == '_' {
		l.readChar()
	}
	return l.input[start : l.pos-1]
}

// NextToken 获取下一个 token
func (l *Lexer) NextToken() Token {
	l.skipWhitespace()

	var tok Token

	switch l.ch {
	case '(':
		tok = Token{Type: TokenLeftParen, Value: "("}
		l.readChar()
	case ')':
		tok = Token{Type: TokenRightParen, Value: ")"}
		l.readChar()
	case 0:
		tok = Token{Type: TokenEOF, Value: ""}
	default:
		if unicode.IsLetter(l.ch) {
			ident := l.readIdentifier()
			switch strings.ToLower(ident) {
			case "and":
				tok = Token{Type: TokenAnd, Value: ident}
			case "or":
				tok = Token{Type: TokenOr, Value: ident}
			default:
				tok = Token{Type: TokenAttribute, Value: ident}
			}
			return tok
		}
		tok = Token{Type: TokenEOF, Value: ""}
	}

	return tok
}

// Parser 语法分析器
type Parser struct {
	lexer     *Lexer
	curToken  Token
	peekToken Token
}

// NewParser 创建新的语法分析器
func NewParser(input string) *Parser {
	p := &Parser{lexer: NewLexer(input)}
	// 读取两个 token，初始化 curToken 和 peekToken
	p.nextToken()
	p.nextToken()
	return p
}

func (p *Parser) nextToken() {
	p.curToken = p.peekToken
	p.peekToken = p.lexer.NextToken()
}

func (p *Parser) curTokenIs(t TokenType) bool {
	return p.curToken.Type == t
}

func (p *Parser) expectPeek(t TokenType) bool {
	if p.peekToken.Type == t {
		p.nextToken()
		return true
	}
	return false
}

// Parse 解析表达式
func (p *Parser) Parse() (*BinaryAccessTree, error) {
	return p.parseOrExpression()
}

// parseOrExpression 解析 OR 表达式（最低优先级）
func (p *Parser) parseOrExpression() (*BinaryAccessTree, error) {
	left, err := p.parseAndExpression()
	if err != nil {
		return nil, err
	}

	for p.peekToken.Type == TokenOr {
		p.nextToken() // 消费 'or'
		p.nextToken() // 移动到右操作数
		right, err := p.parseAndExpression()
		if err != nil {
			return nil, err
		}
		left = NewBinaryAccessTree(NodeTypeOr, fr.Element{}, left, right)
	}

	return left, nil
}

// parseAndExpression 解析 AND 表达式（较高优先级）
func (p *Parser) parseAndExpression() (*BinaryAccessTree, error) {
	left, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}

	for p.peekToken.Type == TokenAnd {
		p.nextToken() // 消费 'and'
		p.nextToken() // 移动到右操作数
		right, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		left = NewBinaryAccessTree(NodeTypeAnd, fr.Element{}, left, right)
	}

	return left, nil
}

// parsePrimary 解析基本表达式（属性或括号表达式）
func (p *Parser) parsePrimary() (*BinaryAccessTree, error) {
	switch p.curToken.Type {
	case TokenAttribute:
		// 属性节点
		attrValue := hash.ToField(p.curToken.Value)
		return NewBinaryAccessTree(NodeTypeLeave, attrValue, nil, nil), nil

	case TokenLeftParen:
		// 括号表达式
		p.nextToken() // 跳过 '('
		expr, err := p.parseOrExpression()
		if err != nil {
			return nil, err
		}
		if !p.expectPeek(TokenRightParen) {
			return nil, fmt.Errorf("expected ')', got %v", p.peekToken)
		}
		return expr, nil

	default:
		return nil, fmt.Errorf("unexpected token: %v", p.curToken)
	}
}

// ParseBooleanFormula 解析布尔表达式字符串并返回二叉树
// 示例: "(A and B) or C", "A or (B and C)", "((A or B) and (C or D))"
func ParseBooleanFormula(formula string) (*BinaryAccessTree, error) {
	parser := NewParser(formula)
	return parser.Parse()
}

// MustParseBooleanFormula 解析布尔表达式，如果失败则 panic（方便测试使用）
func MustParseBooleanFormula(formula string) *BinaryAccessTree {
	tree, err := ParseBooleanFormula(formula)
	if err != nil {
		panic(fmt.Sprintf("failed to parse formula '%s': %v", formula, err))
	}
	return tree
}
