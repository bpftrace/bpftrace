#ifndef EXPRESSION_H__
#define EXPRESSION_H__

// NOLINTBEGIN(modernize-macro-to-enum) - shared with BPF C code
#define MAX_EXPR_INSTRUCTIONS 32

// OPs without arguments
#define EXPR_OP_DEREF   0x01
#define EXPR_OP_AND     0x02
#define EXPR_OP_GE      0x03
#define EXPR_OP_SHL     0x04
#define EXPR_OP_PLUS    0x05
#define EXPR_OP_MUL     0x06
// OPs with one 8 bit argument
// OPs with one 64 bit argument
#define EXPR_OP_CONST   0x81
#define EXPR_OP_PLUS_CONST 0x82
// OPs with one 8 bit and one 64 bit argument
#define EXPR_OP_BREG    0xc1
// NOLINTEND(modernize-macro-to-enum)

#endif // EXPRESSION_H__
